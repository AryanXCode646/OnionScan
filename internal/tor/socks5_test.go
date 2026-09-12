package tor

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestDialContext_StalledProxyTimeout(t *testing.T) {
	// Mock server accepts TCP connection but never sends SOCKS5 greeting reply
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			// Don't send anything back, just keep connection open
			buf := make([]byte, 128)
			_, _ = c.Read(buf)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	conn, err := DialContext(ctx, ln.Addr().String(), "target.onion:80")
	elapsed := time.Since(start)

	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("expected error from stalled proxy, got nil")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Errorf("expected deadline exceeded or timeout error, got: %v", err)
		}
	}

	if elapsed > 1*time.Second {
		t.Errorf("DialContext took %v, expected timeout around 100ms", elapsed)
	}
}

func TestDialContext_ContextCancelledBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := DialContext(ctx, "127.0.0.1:9050", "target.onion:80")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestDialContext_ContextCancelledDuringHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			buf := make([]byte, 128)
			_, _ = c.Read(buf)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	_, err = DialContext(ctx, ln.Addr().String(), "target.onion:80")
	if err == nil {
		t.Fatalf("expected context cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestDialContext_ContextCancelledDuringConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()

			// Read version & greeting
			buf := make([]byte, 128)
			n, err := c.Read(buf)
			if err != nil || n < 2 {
				return
			}

			// Respond to handshake successfully
			_, _ = c.Write([]byte{socksVersion5, authNone})

			// Hang on connect request without sending reply
			_, _ = c.Read(buf)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	_, err = DialContext(ctx, ln.Addr().String(), "target.onion:80")
	if err == nil {
		t.Fatalf("expected context cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestDialContext_DeadlineClearedOnSuccess(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	go func() {
		conn, err := targetLn.Accept()
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 128)
			n, _ := conn.Read(buf)
			_, _ = conn.Write(append([]byte("echo: "), buf[:n]...))
		}
	}()

	socksAddr, cleanup := startMockSOCKS5(t)
	defer cleanup()

	// Dial with a short deadline
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	conn, err := DialContext(ctx, socksAddr, targetLn.Addr().String())
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	// Wait 250ms so that the initial 200ms context deadline has expired.
	time.Sleep(250 * time.Millisecond)

	// Since DialContext clears the connection deadline on success, this write/read must succeed.
	msg := []byte("hello after deadline")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write failed after original deadline: %v", err)
	}

	reply := make([]byte, 128)
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("Read failed after original deadline: %v", err)
	}

	expected := "echo: hello after deadline"
	if string(reply[:n]) != expected {
		t.Errorf("expected %q, got %q", expected, string(reply[:n]))
	}
}

// mockSocks5Server starts a TCP listener and runs fn in a goroutine for each accepted connection.
func mockSocks5Server(t *testing.T, fn func(net.Conn)) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go fn(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// TestHandshake_Success verifies a proper SOCKS5 greeting is accepted.
func TestHandshake_Success(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 3)
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Write([]byte{socksVersion5, authNone})
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := handshake(conn); err != nil {
		t.Errorf("handshake() unexpected error: %v", err)
	}
}

// TestHandshake_WrongVersion verifies rejection of incorrect SOCKS version byte.
func TestHandshake_WrongVersion(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 3)
		_, _ = io.ReadFull(c, buf)
		// reply with version 4 instead of 5
		_, _ = c.Write([]byte{0x04, authNone})
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	err = handshake(conn)
	if err == nil {
		t.Error("handshake() expected error for version mismatch, got nil")
	}
}

// TestHandshake_UnsupportedAuth verifies rejection when server requires auth.
func TestHandshake_UnsupportedAuth(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 3)
		_, _ = io.ReadFull(c, buf)
		// reply: version ok, but requires username/password (0x02)
		_, _ = c.Write([]byte{socksVersion5, 0x02})
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	err = handshake(conn)
	if err == nil {
		t.Error("handshake() expected error for unsupported auth, got nil")
	}
}

// TestHandshake_TruncatedResponse verifies EOF during handshake reply is an error.
func TestHandshake_TruncatedResponse(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 3)
		_, _ = io.ReadFull(c, buf)
		// send only 1 byte — truncated
		_, _ = c.Write([]byte{socksVersion5})
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	err = handshake(conn)
	if err == nil {
		t.Error("handshake() expected error for truncated response, got nil")
	}
}

// TestHandshake_ConnectionClosed verifies immediate close is reported as error.
func TestHandshake_ConnectionClosed(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		c.Close() // close immediately without sending anything
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	err = handshake(conn)
	if err == nil {
		t.Error("handshake() expected error when connection closed immediately, got nil")
	}
}

// TestConnect_Success_IPv4BoundAddr verifies connect succeeds with IPv4 bound address reply.
func TestConnect_Success_IPv4BoundAddr(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		// Reply: VER=5 REP=0 RSV=0 ATYP=IPv4 ADDR=0.0.0.0 PORT=0
		_, _ = c.Write([]byte{socksVersion5, repSucceeded, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := connect(conn, "example.com", 80); err != nil {
		t.Errorf("connect() unexpected error: %v", err)
	}
}

// TestConnect_Success_DomainBoundAddr verifies connect succeeds with domain-name bound address reply.
func TestConnect_Success_DomainBoundAddr(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		// ATYP=0x03 (domain) bound addr "localhost" (9 bytes) + port (2 bytes)
		domain := "localhost"
		resp := []byte{socksVersion5, repSucceeded, 0x00, 0x03, byte(len(domain))}
		resp = append(resp, []byte(domain)...)
		resp = append(resp, 0x00, 0x50) // port 80
		_, _ = c.Write(resp)
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := connect(conn, "example.com", 80); err != nil {
		t.Errorf("connect() unexpected error with domain bound addr: %v", err)
	}
}

// TestConnect_Success_IPv6BoundAddr verifies connect succeeds with IPv6 bound address reply.
func TestConnect_Success_IPv6BoundAddr(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		// Reply: VER=5 REP=0 RSV=0 ATYP=IPv6 (16 bytes) + PORT (2 bytes)
		resp := []byte{socksVersion5, repSucceeded, 0x00, 0x04}
		resp = append(resp, make([]byte, 16)...) // 16 zero bytes
		resp = append(resp, 0x00, 0x50)          // port 80
		_, _ = c.Write(resp)
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := connect(conn, "example.com", 80); err != nil {
		t.Errorf("connect() unexpected error with IPv6 bound addr: %v", err)
	}
}

// TestConnect_NonSuccessReplyCode verifies error when reply code is non-zero.
func TestConnect_NonSuccessReplyCode(t *testing.T) {
	repCodes := []struct {
		code byte
		desc string
	}{
		{0x01, "general SOCKS server failure"},
		{0x02, "connection not allowed by ruleset"},
		{0x03, "network unreachable"},
		{0x04, "host unreachable"},
		{0x05, "connection refused"},
		{0x06, "TTL expired"},
	}

	for _, tc := range repCodes {
		t.Run(tc.desc, func(t *testing.T) {
			addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte{socksVersion5, tc.code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			})
			defer cleanup()

			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			if err := connect(conn, "example.com", 80); err == nil {
				t.Errorf("connect() expected error for repCode 0x%02x (%s), got nil", tc.code, tc.desc)
			}
		})
	}
}

// TestConnect_UnknownBoundAddrType verifies error when ATYP in reply is not 1, 3, or 4.
func TestConnect_UnknownBoundAddrType(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		// ATYP=0xFF (unknown)
		_, _ = c.Write([]byte{socksVersion5, repSucceeded, 0x00, 0xFF})
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := connect(conn, "example.com", 80); err == nil {
		t.Error("connect() expected error for unknown bound address type 0xFF, got nil")
	}
}

// TestConnect_TruncatedHeader verifies error when response has fewer than 4 bytes.
func TestConnect_TruncatedHeader(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		// send only 2 bytes then close
		_, _ = c.Write([]byte{socksVersion5, repSucceeded})
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := connect(conn, "example.com", 80); err == nil {
		t.Error("connect() expected error for truncated connect header, got nil")
	}
}

// TestConnect_TruncatedIPv4BoundAddr verifies error when IPv4 bound addr bytes are missing.
func TestConnect_TruncatedIPv4BoundAddr(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		// ATYP=0x01 (IPv4, needs 6 bytes), but send only 2 bytes then close
		_, _ = c.Write([]byte{socksVersion5, repSucceeded, 0x00, 0x01, 1, 2})
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := connect(conn, "example.com", 80); err == nil {
		t.Error("connect() expected error for truncated IPv4 bound address, got nil")
	}
}

// TestConnect_HostnameTooLong verifies that a hostname > 255 bytes is rejected.
func TestConnect_HostnameTooLong(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	longHost := make([]byte, 256)
	for i := range longHost {
		longHost[i] = 'a'
	}

	if err := connect(conn, string(longHost), 80); err == nil {
		t.Error("connect() expected error for hostname > 255 bytes, got nil")
	}
}

// TestDialContext_InvalidTargetAddr verifies DialContext returns an error if targetAddr is malformed.
func TestDialContext_InvalidTargetAddr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	socksAddr, cleanup := startMockSOCKS5(t)
	defer cleanup()

	conn, err := DialContext(ctx, socksAddr, "not-a-host-port")
	if err == nil {
		conn.Close()
		t.Error("expected error for malformed target address, got nil")
	}
}

// TestDialContext_InvalidPort verifies DialContext returns an error if port is not a valid int.
func TestDialContext_InvalidPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	socksAddr, cleanup := startMockSOCKS5(t)
	defer cleanup()

	conn, err := DialContext(ctx, socksAddr, "example.onion:notaport")
	if err == nil {
		conn.Close()
		t.Error("expected error for non-integer port, got nil")
	}
}

// TestConnect_TruncatedDomainName verifies error when domain bound address bytes are truncated.
func TestConnect_TruncatedDomainName(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		// ATYP=0x03, domain len = 10, but send only 3 bytes of domain then close
		_, _ = c.Write([]byte{socksVersion5, repSucceeded, 0x00, 0x03, 10, 'a', 'b', 'c'})
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := connect(conn, "example.com", 80); err == nil {
		t.Error("expected error for truncated domain bound address, got nil")
	}
}

// TestConnect_TruncatedIPv6 verifies error when IPv6 bound address bytes are truncated.
func TestConnect_TruncatedIPv6(t *testing.T) {
	addr, cleanup := mockSocks5Server(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		// ATYP=0x04, but send only 8 bytes instead of 16+2 then close
		_, _ = c.Write([]byte{socksVersion5, repSucceeded, 0x00, 0x04, 1, 2, 3, 4, 5, 6, 7, 8})
	})
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := connect(conn, "example.com", 80); err == nil {
		t.Error("expected error for truncated IPv6 bound address, got nil")
	}
}

// TestReadFull_ShortReadError verifies readFull returns an error if EOF occurs before buffer is filled.
func TestReadFull_ShortReadError(t *testing.T) {
	r, w := net.Pipe()
	go func() {
		_, _ = w.Write([]byte{1, 2})
		_ = w.Close()
	}()
	buf := make([]byte, 5)
	n, err := readFull(r, buf)
	_ = r.Close()
	if err == nil {
		t.Errorf("expected error from readFull on short read, got nil (n=%d)", n)
	}
	if n != 2 {
		t.Errorf("expected n=2, got %d", n)
	}
}
