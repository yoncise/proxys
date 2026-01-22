# proxys

A lightweight SNI-based TLS reverse proxy with per-route SOCKS5 proxy support.

## Features

- SNI-based routing: Routes TLS connections based on the Server Name Indication (SNI) hostname
- Per-route SOCKS5 proxy: Each route can optionally specify its own SOCKS5 proxy
- Passthrough mode: Forward connections directly to the SNI hostname
- Route mode: Forward connections to a different backend server
- Multiple routes: Configure multiple routes with different proxy settings

## Installation

```bash
go build
```

## Usage

```bash
./proxys -listen <address> -route <route1> -route <route2> ...
```

### Flags

- `-listen <address>`: Listen address (default: `:443`)
- `-route <route>`: SNI route mapping (can be specified multiple times)

### Route Syntax

```
<hostname>[@<proxy>]                  # Passthrough to hostname:443
<hostname>=<target>[@<proxy>]         # Route to specific target
<hostname>=:<port>[@<proxy>]          # Route to localhost:port
```

**Components:**
- `<hostname>`: SNI hostname to match
- `<target>`: Backend target in `host:port` format
- `:<port>`: Shorthand for `localhost:port`
- `@<proxy>`: Optional SOCKS5 proxy in `host:port` format

## Examples

### Basic Usage

**Passthrough to example.com:443 (direct connection):**
```bash
./proxys -listen :443 -route example.com
```

**Route to local backend:**
```bash
./proxys -listen :443 -route example.com=:8080
```

**Route to specific backend:**
```bash
./proxys -listen :443 -route example.com=backend.local:443
```

### Using SOCKS5 Proxy

**Passthrough via SOCKS5 proxy:**
```bash
./proxys -listen :443 -route example.com@localhost:1080
```

**Route to local backend via SOCKS5:**
```bash
./proxys -listen :443 -route example.com=:8080@localhost:1080
```

**Route to specific backend via SOCKS5:**
```bash
./proxys -listen :443 -route example.com=backend.local:443@localhost:1080
```

### Multiple Routes

**Different routes with different proxy configurations:**
```bash
./proxys -listen :443 \
  -route example.com=:8080@localhost:1080 \
  -route api.example.com=:9000@localhost:1081 \
  -route direct.example.com=:7000 \
  -route passthrough.example.com@localhost:1080
```

## How It Works

1. The proxy listens for incoming TLS connections
2. Reads the ClientHello message to extract the SNI hostname
3. Looks up the hostname in the configured routes
4. If a route exists:
   - Creates a dialer (direct or via SOCKS5 proxy based on route configuration)
   - Connects to the backend (passthrough or routed target)
   - Relays the TLS connection bidirectionally
5. If no route exists, the connection is rejected

## Security Notes

- This proxy does not terminate TLS connections
- All TLS handshakes and encryption happen end-to-end between client and backend
- The proxy only inspects the unencrypted SNI field in the ClientHello
- Routes act as an allowlist: only configured hostnames are permitted

## License

MIT
