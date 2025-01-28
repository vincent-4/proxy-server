# Terminal UI HTTP/HTTPS Proxy Server

An interactive proxy server with a beautiful Terminal User Interface (TUI) built using [Bubbletea][bubbletea]. Monitor your proxy traffic in real-time with a clean, responsive interface.

## Features

- HTTP and HTTPS proxy support
- Real-time metrics display using [Bubbletea][bubbletea] and [bubbles][]
- Basic authentication with rate limiting
- Circuit breaker for failing hosts
- Connection pooling and retry logic
- Request/response size limits
- Bandwidth usage tracking
- Beautiful UI styling with [lipgloss][]

## Usage

### Environment Variables (Optional)
```bash
PROXY_PORT=8080        # Port to run the proxy server on
PROXY_USERNAME=admin   # Username for basic auth
PROXY_PASSWORD=password # Password for basic auth
```

### Command Line Flags
```bash
--port string      Port to run the proxy server on (default "8080")
--username string  Username for basic auth (default "admin")
--password string  Password for basic auth (default "password")
```

### Running the Server

```bash
# Run with default settings. In the future there may be CLI configs.
go run main.go
```

### TUI Controls
- Press 's' to start/stop the proxy server
- Press 'tab' to focus/blur the metrics table
- Press 'q' to quit

## Using the Proxy

```bash
# Example using curl
curl -x http://localhost:8080 --proxy-user admin:password http://example.com
```

## Security Notes
- Basic authentication is sent in clear text unless HTTPS is used
- Rate limiting is applied to authentication attempts
- Maximum request/response size is limited to 10MB
- Connection pooling with configurable limits
- Circuit breaker protection against failing hosts

## Credits

Built with these amazing libraries:
- [bubbletea][] - Terminal UI framework
- [bubbles][] - TUI components
- [lipgloss][] - Style definitions
- [goreleaser][] - Release automation
- [lint][] - Code quality

## Development

### Prerequisites
- Go 1.23.5 or later
- Terminal with true color support (recommended)

### Building from Source
```bash
git clone https://github.com/yourusername/proxy-server.git
cd proxy-server
go build
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

[bubbletea]: https://github.com/charmbracelet/bubbletea
[bubbles]: https://github.com/charmbracelet/bubbles
[lipgloss]: https://github.com/charmbracelet/lipgloss
[goreleaser]: https://goreleaser.com
[lint]: https://golangci-lint.run
