package cycletlsR

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type errorMessage struct {
	StatusCode int
	debugger   string
	ErrorMsg   string
	Op         string
}

func lastString(ss []string) string {
	return ss[len(ss)-1]
}

// func createErrorString(err: string) (msg, debugger string) {
func createErrorString(err error) (msg, debugger string) {
	msg = fmt.Sprintf("Request returned a Syscall Error: %s", err)
	debugger = fmt.Sprintf("%#v\n", err)
	return
}

func createErrorMessage(StatusCode int, err error, op string) errorMessage {
	msg := fmt.Sprintf("Request returned a Syscall Error: %s", err)
	debugger := fmt.Sprintf("%#v\n", err)
	return errorMessage{StatusCode: StatusCode, debugger: debugger, ErrorMsg: msg, Op: op}
}

func parseError(err error) (errormessage errorMessage) {
	if err == nil {
		return errorMessage{StatusCode: 500, debugger: "no error provided", ErrorMsg: "Unknown error: nil was passed to parseError", Op: "unknown"}
	}

	// Значение по умолчанию для операции
	op := "unknown"

	// Проверяем наличие кода состояния в сообщении об ошибке
	httpError := err.Error()
	parts := strings.Split(httpError, "StatusCode:")

	if len(parts) > 1 {
		// Есть StatusCode в сообщении
		statusStr := strings.TrimSpace(parts[len(parts)-1])
		if statusCode, convErr := strconv.Atoi(statusStr); convErr == nil && statusCode != 0 {
			msg, debugger := createErrorString(err)
			return errorMessage{StatusCode: statusCode, debugger: debugger, ErrorMsg: msg, Op: op}
		}
	}

	// Обработка различных типов ошибок с поддержкой wrapped errors
	var uerr *url.Error
	if errors.As(err, &uerr) {
		var noerr *net.OpError
		if errors.As(uerr.Err, &noerr) {
			if noerr.Op != "" {
				op = noerr.Op
			}

			var syscallErr *os.SyscallError
			var addrErr *net.AddrError
			var dnsErr *net.DNSError

			switch {
			case errors.As(noerr.Err, &syscallErr):
				if noerr.Timeout() {
					return createErrorMessage(408, syscallErr, op) // Timeout
				}
				return createErrorMessage(401, syscallErr, op) // Other syscall errors

			case errors.As(noerr.Err, &addrErr):
				return createErrorMessage(405, addrErr, op) // Address errors

			case errors.As(noerr.Err, &dnsErr):
				return createErrorMessage(421, dnsErr, op) // DNS errors

			default:
				return createErrorMessage(421, noerr, op) // Other network operation errors
			}
		}

		if uerr.Timeout() {
			return createErrorMessage(408, uerr, op) // URL timeout
		}

		// Другие URL ошибки
		return createErrorMessage(400, uerr, op)
	}

	// TLS ошибки
	if strings.Contains(httpError, "tls:") || strings.Contains(httpError, "x509:") {
		return createErrorMessage(525, err, "tls_handshake")
	}

	// Общий случай - ошибка неизвестного типа
	return createErrorMessage(500, err, op)
}

type errExtensionNotExist struct {
	Context string
}

func (w *errExtensionNotExist) Error() string {
	return fmt.Sprintf("Extension {{ %s }} is not Supported by CycleTLS please raise an issue", w.Context)
}

func raiseExtensionError(info string) *errExtensionNotExist {
	return &errExtensionNotExist{
		Context: info,
	}
}
