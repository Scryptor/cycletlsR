package cycletlsR

import (
	"context"
	"errors"
	"fmt"
	"net"

	"strings"
	"sync"

	http "github.com/Scryptor/fhttp"
	http2 "github.com/Scryptor/fhttp/http2"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

var errProtocolNegotiated = errors.New("protocol negotiated")

type roundTripper struct {
	sync.Mutex
	// fix typing
	JA3       string
	UserAgent string

	InsecureSkipVerify bool
	Cookies            []Cookie
	cachedConnections  map[string]net.Conn
	cachedTransports   map[string]http.RoundTripper

	dialer     proxy.ContextDialer
	forceHTTP1 bool
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Fix this later for proper cookie parsing
	for _, properties := range rt.Cookies {
		req.AddCookie(&http.Cookie{
			Name:       properties.Name,
			Value:      properties.Value,
			Path:       properties.Path,
			Domain:     properties.Domain,
			Expires:    properties.JSONExpires.Time, //TODO: scuffed af
			RawExpires: properties.RawExpires,
			MaxAge:     properties.MaxAge,
			HttpOnly:   properties.HTTPOnly,
			Secure:     properties.Secure,
			Raw:        properties.Raw,
			Unparsed:   properties.Unparsed,
		})
	}
	req.Header.Set("User-Agent", rt.UserAgent)
	addr := rt.getDialTLSAddr(req)
	if _, ok := rt.cachedTransports[addr]; !ok {
		if err := rt.getTransport(req, addr); err != nil {
			return nil, err
		}
	}
	return rt.cachedTransports[addr].RoundTrip(req)
}

func (rt *roundTripper) getTransport(req *http.Request, addr string) error {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		rt.cachedTransports[addr] = &http.Transport{DialContext: rt.dialer.DialContext, DisableKeepAlives: true}
		return nil
	case "https":
	default:
		return fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
	}

	_, err := rt.dialTLS(req.Context(), "tcp", addr)
	switch err {
	case errProtocolNegotiated:
	case nil:
		// Should never happen.
		panic("dialTLS returned no error when determining cachedTransports")
	default:
		return err
	}

	return nil
}

func (rt *roundTripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	// Первая блокировка для проверки кеша
	rt.Lock()
	if conn := rt.cachedConnections[addr]; conn != nil {
		rt.Unlock()
		return conn, nil
	}
	rt.Unlock()

	// Выполняем дорогостоящие операции без удержания блокировки
	rawConn, err := rt.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	spec, err := StringToSpec(rt.JA3, rt.UserAgent, rt.forceHTTP1)
	if err != nil {
		rawConn.Close() // Закрываем соединение при ошибке
		return nil, err
	}

	conn := utls.UClient(rawConn, &utls.Config{ServerName: host, OmitEmptyPsk: true, InsecureSkipVerify: rt.InsecureSkipVerify}, utls.HelloCustom)

	if err := conn.ApplyPreset(spec); err != nil {
		rawConn.Close() // Закрываем соединение при ошибке
		return nil, err
	}

	if err = conn.Handshake(); err != nil {
		conn.Close() // Закрываем соединение при ошибке рукопожатия
		if err.Error() == "tls: CurvePreferences includes unsupported curve" {
			return nil, fmt.Errorf("conn.Handshake() error for tls 1.3 (please retry request): %+v", err)
		}
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	// Вторая блокировка для обновления кешей
	rt.Lock()
	defer rt.Unlock()

	// Проверяем, не добавило ли другое горутину соединение в кеш, пока мы работали
	if existingConn := rt.cachedConnections[addr]; existingConn != nil {
		// Используем существующее соединение вместо только что созданного
		conn.Close() // Закрываем наше соединение, так как будем использовать существующее
		return existingConn, nil
	}

	// Проверяем, есть ли у нас уже транспорт для этого адреса
	if rt.cachedTransports[addr] != nil {
		// Кешируем наше соединение и возвращаем его
		rt.cachedConnections[addr] = conn
		return conn, nil
	}

	// Создаем новый транспорт на основе согласованного протокола
	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		parsedUserAgent := parseUserAgent(rt.UserAgent)
		t2 := http2.Transport{
			DialTLS:     rt.dialTLSHTTP2,
			PushHandler: &http2.DefaultPushHandler{},
			Navigator:   parsedUserAgent.UserAgent,
		}
		rt.cachedTransports[addr] = &t2
	default:
		// HTTP 1.x поверх TLS
		rt.cachedTransports[addr] = &http.Transport{DialTLSContext: rt.dialTLS, DisableKeepAlives: true}
	}

	// Кешируем созданное нами соединение
	rt.cachedConnections[addr] = conn

	// Сигнализируем, что вызывающий код должен повторить попытку с новым транспортом
	return nil, errProtocolNegotiated
}

func (rt *roundTripper) dialTLSHTTP2(network, addr string, _ *utls.Config) (net.Conn, error) {
	return rt.dialTLS(context.Background(), network, addr)
}

func (rt *roundTripper) getDialTLSAddr(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(req.URL.Host, "443") // we can assume port is 443 at this point
}

func (rt *roundTripper) CloseIdleConnections() {
	for addr, conn := range rt.cachedConnections {
		_ = conn.Close()
		delete(rt.cachedConnections, addr)
	}
}

func newRoundTripper(browser Browser, dialer ...proxy.ContextDialer) http.RoundTripper {
	if len(dialer) > 0 {

		return &roundTripper{
			dialer:             dialer[0],
			JA3:                browser.JA3,
			UserAgent:          browser.UserAgent,
			Cookies:            browser.Cookies,
			cachedTransports:   make(map[string]http.RoundTripper),
			cachedConnections:  make(map[string]net.Conn),
			InsecureSkipVerify: browser.InsecureSkipVerify,
			forceHTTP1:         browser.forceHTTP1,
		}
	}

	return &roundTripper{
		dialer:             proxy.Direct,
		JA3:                browser.JA3,
		UserAgent:          browser.UserAgent,
		Cookies:            browser.Cookies,
		cachedTransports:   make(map[string]http.RoundTripper),
		cachedConnections:  make(map[string]net.Conn),
		InsecureSkipVerify: browser.InsecureSkipVerify,
		forceHTTP1:         browser.forceHTTP1,
	}
}
