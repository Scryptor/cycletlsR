package cycletlsR

// borrowed from from https://github.com/caddyserver/forwardproxy/blob/master/httpclient/httpclient.go
import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"

	http "github.com/Scryptor/fhttp"
	http2 "github.com/Scryptor/fhttp/http2"
	"golang.org/x/net/proxy"
	"h12.io/socks"
)

type SocksDialer struct {
	socksDial func(string, string) (net.Conn, error)
}

func (d *SocksDialer) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	return d.socksDial(network, addr)
}

func (d *SocksDialer) Dial(network, addr string) (net.Conn, error) {
	return d.socksDial(network, addr)
}

// connectDialer allows to configure one-time use HTTP CONNECT client
type connectDialer struct {
	ProxyURL      url.URL
	DefaultHeader http.Header

	Dialer proxy.ContextDialer // overridden dialer allow to control establishment of TCP connection

	// overridden DialTLS allows user to control establishment of TLS connection
	// MUST return connection with completed Handshake, and NegotiatedProtocol
	DialTLS func(network string, address string) (net.Conn, string, error)

	EnableH2ConnReuse  bool
	cacheH2Mu          sync.Mutex
	cachedH2ClientConn *http2.ClientConn
	cachedH2RawConn    net.Conn
}

// newConnectDialer creates a dialer to issue CONNECT requests and tunnel traffic via HTTP/S proxy.
// proxyUrlStr must provide Scheme and Host, may provide credentials and port.
// Example: https://username:password@golang.org:443
func newConnectDialer(proxyURLStr string, UserAgent string) (proxy.ContextDialer, error) {
	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, err
	}

	if proxyURL.Host == "" || proxyURL.Host == "undefined" {
		return nil, errors.New("invalid url `" + proxyURLStr +
			"`, make sure to specify full url like https://username:password@hostname.com:443/")
	}

	client := &connectDialer{
		ProxyURL:          *proxyURL,
		DefaultHeader:     make(http.Header),
		EnableH2ConnReuse: true,
	}

	switch proxyURL.Scheme {
	case "http":
		if proxyURL.Port() == "" {
			proxyURL.Host = net.JoinHostPort(proxyURL.Host, "80")
		}
	case "https":
		if proxyURL.Port() == "" {
			proxyURL.Host = net.JoinHostPort(proxyURL.Host, "443")
		}
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if proxyURL.User != nil {
			if proxyURL.User.Username() != "" {
				username := proxyURL.User.Username()
				password, _ := proxyURL.User.Password()
				auth = &proxy.Auth{User: username, Password: password}
			}
		}
		var forward proxy.Dialer
		if proxyURL.Scheme == "socks5h" {
			forward = proxy.Direct
		}
		dialSocksProxy, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, forward)
		if err != nil {
			return nil, fmt.Errorf("Error creating SOCKS5 proxy, reason %s", err)
		}
		if contextDialer, ok := dialSocksProxy.(proxy.ContextDialer); ok {
			client.Dialer = contextDialer
		} else {
			return nil, errors.New("failed type assertion to DialContext")
		}
		client.DefaultHeader.Set("User-Agent", UserAgent)
		return client, nil
	case "socks4":
		var dialer *SocksDialer
		dialer = &SocksDialer{socks.DialSocksProxy(socks.SOCKS4, proxyURL.Host)}
		client.Dialer = dialer
		client.DefaultHeader.Set("User-Agent", UserAgent)
		return client, nil
	case "":
		return nil, errors.New("specify scheme explicitly (https://)")
	default:
		return nil, errors.New("scheme " + proxyURL.Scheme + " is not supported")
	}

	client.Dialer = &net.Dialer{}

	if proxyURL.User != nil {
		if proxyURL.User.Username() != "" {
			// password, _ := proxyUrl.User.Password()
			// transport.DefaultHeader.Set("Proxy-Authorization", "Basic "+
			// 	base64.StdEncoding.EncodeToString([]byte(proxyUrl.User.Username()+":"+password)))

			username := proxyURL.User.Username()
			password, _ := proxyURL.User.Password()

			// transport.DefaultHeader.SetBasicAuth(username, password)
			auth := username + ":" + password
			basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			client.DefaultHeader.Add("Proxy-Authorization", basicAuth)
		}
	}
	client.DefaultHeader.Set("User-Agent", UserAgent)
	return client, nil
}

func (c *connectDialer) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

// ContextKeyHeader Users of context.WithValue should define their own types for keys
type ContextKeyHeader struct{}

// ctx.Value will be inspected for optional ContextKeyHeader{} key, with `http.Header` value,
// which will be added to outgoing request headers, overriding any colliding c.DefaultHeader
func (c *connectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c.ProxyURL.Scheme == "socks5" || c.ProxyURL.Scheme == "socks4" || c.ProxyURL.Scheme == "socks5h" {
		return c.Dialer.DialContext(ctx, network, address)
	}

	req := (&http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: address},
		Header: make(http.Header),
		Host:   address,
	}).WithContext(ctx)
	for k, v := range c.DefaultHeader {
		req.Header[k] = v
	}
	if ctxHeader, ctxHasHeader := ctx.Value(ContextKeyHeader{}).(http.Header); ctxHasHeader {
		for k, v := range ctxHeader {
			req.Header[k] = v
		}
	}
	connectHTTP2 := func(rawConn net.Conn, h2clientConn *http2.ClientConn) (net.Conn, error) {
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		pr, pw := io.Pipe()
		req.Body = pr

		resp, err := h2clientConn.RoundTrip(req)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			_ = rawConn.Close()
			return nil, errors.New("Proxy responded with non 200 code: " + resp.Status + "StatusCode:" + strconv.Itoa(resp.StatusCode))
		}
		return newHTTP2Conn(rawConn, pw, resp.Body), nil
	}

	connectHTTP1 := func(rawConn net.Conn) (net.Conn, error) {
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		err := req.Write(rawConn)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		resp, err := http.ReadResponse(bufio.NewReader(rawConn), req)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			_ = rawConn.Close()
			return nil, errors.New("Proxy responded with non 200 code: " + resp.Status + " StatusCode:" + strconv.Itoa(resp.StatusCode))
		}
		return rawConn, nil
	}

	if c.EnableH2ConnReuse {
		c.cacheH2Mu.Lock()
		unlocked := false
		if c.cachedH2ClientConn != nil && c.cachedH2RawConn != nil {
			if c.cachedH2ClientConn.CanTakeNewRequest() {
				rc := c.cachedH2RawConn
				cc := c.cachedH2ClientConn
				c.cacheH2Mu.Unlock()
				unlocked = true
				proxyConn, err := connectHTTP2(rc, cc)
				if err == nil {
					return proxyConn, err
				}
				// else: carry on and try again
			}
		}
		if !unlocked {
			c.cacheH2Mu.Unlock()
		}
	}

	var err error
	var rawConn net.Conn
	negotiatedProtocol := ""
	switch c.ProxyURL.Scheme {
	case "http":
		rawConn, err = c.Dialer.DialContext(ctx, network, c.ProxyURL.Host)
		if err != nil {
			return nil, err
		}
	case "https":
		if c.DialTLS != nil {
			rawConn, negotiatedProtocol, err = c.DialTLS(network, c.ProxyURL.Host)
			if err != nil {
				return nil, err
			}
		} else {
			tlsConf := tls.Config{
				NextProtos:         []string{"h2", "http/1.1"},
				ServerName:         c.ProxyURL.Hostname(),
				InsecureSkipVerify: true,
			}
			tlsConn, err := tls.Dial(network, c.ProxyURL.Host, &tlsConf)
			if err != nil {
				return nil, err
			}
			err = tlsConn.Handshake()
			if err != nil {
				return nil, err
			}
			negotiatedProtocol = tlsConn.ConnectionState().NegotiatedProtocol
			rawConn = tlsConn
		}
	default:
		return nil, errors.New("scheme " + c.ProxyURL.Scheme + " is not supported")
	}

	switch negotiatedProtocol {
	case "":
		fallthrough
	case "http/1.1":
		return connectHTTP1(rawConn)
	case "h2":
		//TODO: update this with correct navigator
		t := http2.Transport{Navigator: "chrome"}
		h2clientConn, err := t.NewClientConn(rawConn)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		proxyConn, err := connectHTTP2(rawConn, h2clientConn)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		if c.EnableH2ConnReuse {
			c.cacheH2Mu.Lock()
			c.cachedH2ClientConn = h2clientConn
			c.cachedH2RawConn = rawConn
			c.cacheH2Mu.Unlock()
		}
		return proxyConn, err
	default:
		_ = rawConn.Close()
		return nil, errors.New("negotiated unsupported application layer protocol: " +
			negotiatedProtocol)
	}
}

func newHTTP2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) net.Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	var inErr, outErr error

	if h.in != nil {
		inErr = h.in.Close()
	}

	if h.out != nil {
		outErr = h.out.Close()
	}

	// Возвращаем первую встреченную ошибку
	if inErr != nil {
		return inErr
	}
	return outErr
}

func (h *http2Conn) CloseConn() error {
	return h.Conn.Close()
}

func (h *http2Conn) CloseWrite() error {
	return h.in.Close()
}

func (h *http2Conn) CloseRead() error {
	return h.out.Close()
}
