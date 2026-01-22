package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type routeFlags []string

func (r *routeFlags) String() string {
	return strings.Join(*r, ",")
}

func (r *routeFlags) Set(value string) error {
	*r = append(*r, value)
	return nil
}

// RouteConfig represents a single routing rule
type RouteConfig struct {
	Host        string // SNI hostname to match
	Target      string // Backend target (empty for passthrough)
	Passthrough bool   // If true, connect to Host:443
	ProxyAddr   string // SOCKS5 proxy for this route (optional)
}

// RouteMap stores all routing rules
type RouteMap struct {
	rules map[string]*RouteConfig
}

// Lookup checks if a host is allowed and returns its route config
func (rm *RouteMap) Lookup(host string) (*RouteConfig, bool) {
	cfg, ok := rm.rules[host]
	return cfg, ok
}

var (
	listen string
	routes routeFlags
)

// parseRoutes parses route flags into RouteMap
func parseRoutes(routes []string) (*RouteMap, error) {
	rm := &RouteMap{rules: make(map[string]*RouteConfig)}

	for _, route := range routes {
		cfg, err := parseRoute(route)
		if err != nil {
			return nil, err
		}

		if _, exists := rm.rules[cfg.Host]; exists {
			return nil, fmt.Errorf("duplicate route for host: %s", cfg.Host)
		}

		rm.rules[cfg.Host] = cfg
	}

	return rm, nil
}

// parseRoute parses a single route string
func parseRoute(route string) (*RouteConfig, error) {
	var proxyAddr string
	remainder := route

	// Extract SOCKS5 proxy if @ delimiter present
	if idx := strings.LastIndex(route, "@"); idx != -1 {
		proxyAddr = strings.TrimSpace(route[idx+1:])
		remainder = strings.TrimSpace(route[:idx])

		// Validate proxy address format (must be host:port)
		if proxyAddr != "" {
			if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
				return nil, fmt.Errorf("invalid SOCKS proxy address '%s': %v", proxyAddr, err)
			}
		}
	}

	// Detect and reject old format (in the remainder)
	if strings.Contains(remainder, ":") && !strings.Contains(remainder, "=") {
		return nil, fmt.Errorf("invalid route format '%s'\n"+
			"Use: -route hostname=:port or -route hostname", route)
	}

	// Passthrough format: just hostname
	if !strings.Contains(remainder, "=") {
		host := strings.TrimSpace(remainder)
		if host == "" {
			return nil, fmt.Errorf("empty hostname")
		}
		return &RouteConfig{Host: host, Passthrough: true, ProxyAddr: proxyAddr}, nil
	}

	// Route format: hostname=target
	parts := strings.SplitN(remainder, "=", 2)
	host := strings.TrimSpace(parts[0])
	target := strings.TrimSpace(parts[1])

	if host == "" {
		return nil, fmt.Errorf("empty hostname")
	}
	if target == "" {
		return nil, fmt.Errorf("target required when using '=' syntax")
	}

	// Normalize :port to localhost:port
	if strings.HasPrefix(target, ":") {
		port := target[1:]
		if _, err := strconv.Atoi(port); err != nil {
			return nil, fmt.Errorf("invalid port '%s': %v", port, err)
		}
		target = "localhost" + target
	} else {
		// Validate host:port format
		if _, _, err := net.SplitHostPort(target); err != nil {
			return nil, fmt.Errorf("invalid target '%s': %v", target, err)
		}
	}

	return &RouteConfig{Host: host, Target: target, Passthrough: false, ProxyAddr: proxyAddr}, nil
}

// createDialer creates a dialer function that optionally uses a SOCKS proxy
func createDialer(socksAddr string, timeout time.Duration) (func(network, addr string) (net.Conn, error), error) {
	if socksAddr == "" {
		d := &net.Dialer{Timeout: timeout}
		return d.Dial, nil
	}
	if _, _, err := net.SplitHostPort(socksAddr); err != nil {
		return nil, fmt.Errorf("invalid SOCKS proxy address '%s': %v", socksAddr, err)
	}
	socksDialer, err := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}
	return socksDialer.Dial, nil
}

func main() {
	flag.StringVar(&listen, "listen", ":443", "Listen address")
	flag.Var(&routes, "route", "SNI route mapping (format: hostname[@proxy] or hostname=target[@proxy])")
	flag.Parse()

	// Parse routes with new logic
	routeMap, err := parseRoutes(routes)
	if err != nil {
		log.Fatalf("Failed to parse routes: %v", err)
	}

	// Log configuration
	log.Printf("Starting SNI proxy on %s", listen)
	if len(routeMap.rules) > 0 {
		log.Println("Configured routes:")
		for host, cfg := range routeMap.rules {
			proxyInfo := ""
			if cfg.ProxyAddr != "" {
				proxyInfo = fmt.Sprintf(" via SOCKS5 %s", cfg.ProxyAddr)
			}

			if cfg.Passthrough {
				log.Printf("  %s -> %s:443 (passthrough)%s", host, host, proxyInfo)
			} else {
				log.Printf("  %s -> %s (routed)%s", host, cfg.Target, proxyInfo)
			}
		}
	} else {
		log.Println("Warning: No routes configured - all connections will be rejected")
	}

	l, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConn(conn, routeMap)
	}
}

func handleConn(conn net.Conn, routes *RouteMap) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read ClientHello
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, conn, 5); err != nil {
		log.Printf("Failed to read TLS record header: %v", err)
		return
	}

	length := binary.BigEndian.Uint16(buf.Bytes()[3:5])
	if _, err := io.CopyN(&buf, conn, int64(length)); err != nil {
		log.Printf("Failed to read TLS record: %v", err)
		return
	}

	// Parse SNI
	ch, ok := ParseClientHello(buf.Bytes())
	if !ok || ch.SNI == "" {
		log.Println("Failed to extract SNI")
		return
	}

	// Lookup host in route map (filtering happens here)
	cfg, allowed := routes.Lookup(ch.SNI)
	if !allowed {
		log.Printf("Rejected connection to unconfigured host: %s", ch.SNI)
		return
	}

	// Determine backend based on RouteConfig
	var backend string
	var routeType string

	if cfg.Passthrough {
		backend = ch.SNI + ":443"
		routeType = "passthrough"
	} else {
		backend = cfg.Target
		routeType = "routed"
	}

	log.Printf("%s -> %s (%s)", ch.SNI, backend, routeType)

	// Create dialer based on route's SOCKS proxy setting
	dialer, err := createDialer(cfg.ProxyAddr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to create dialer for %s: %v", ch.SNI, err)
		return
	}

	// Connect to backend
	conn.SetReadDeadline(time.Time{})
	backendConn, err := dialer("tcp", backend)
	if err != nil {
		log.Printf("Failed to connect to backend %s: %v", backend, err)
		return
	}
	defer backendConn.Close()

	// Replay ClientHello to backend
	c := &prefixConn{
		Conn:   conn,
		Reader: io.MultiReader(&buf, conn),
	}

	// Bidirectional copy
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(backendConn, c)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(c, backendConn)
		errCh <- err
	}()

	// Wait for one side to close
	err = <-errCh
	if err != nil && err != io.EOF {
		log.Printf("Copy error for %s: %v", ch.SNI, err)
	}
}

type prefixConn struct {
	net.Conn
	io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}
