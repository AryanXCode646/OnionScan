package tor

import (
	"context"
	"net"
	"net/http"
	"time"
)

// DefaultSOCKSAddr is where a locally-running Tor daemon listens by default.
const DefaultSOCKSAddr = "127.0.0.1:9050"

// NewHTTPClient returns an *http.Client whose transport dials all
// connections through the Tor SOCKS5 proxy at socksAddr. Pass
// DefaultSOCKSAddr unless the user configured a different SOCKSPort.
func NewHTTPClient(socksAddr string, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return DialContext(ctx, socksAddr, addr)
		},
		DisableKeepAlives: false,
		// Response size / count limits belong in the crawler, not here --
		// tracked in issue "Add resource limits to crawler (size/time/pages)".
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}
