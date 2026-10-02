package middleware

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"litellm-oauth-facade/internal/authctx"
)

func requestAttrs(r *http.Request) []any {
	attrs := []any{
		"method", r.Method,
		"path", r.URL.Path,
	}
	if id := chimw.GetReqID(r.Context()); id != "" {
		attrs = append(attrs, "request_id", id)
	}
	if toolset := authctx.Toolset(r.Context()); toolset != "" {
		attrs = append(attrs, "toolset", toolset)
	}
	if ip := r.RemoteAddr; ip != "" {
		attrs = append(attrs, "client_ip", ip)
	}
	return attrs
}

func logAuthDeny(log *slog.Logger, r *http.Request, status int, reason string, extra ...any) {
	if log == nil {
		return
	}
	attrs := requestAttrs(r)
	attrs = append(attrs, "status", status, "reason", reason)
	attrs = append(attrs, extra...)
	log.Warn("auth denied", attrs...)
}

func logAuthSuccess(log *slog.Logger, r *http.Request, extra ...any) {
	if log == nil || !log.Enabled(r.Context(), slog.LevelDebug) {
		return
	}
	attrs := requestAttrs(r)
	attrs = append(attrs, extra...)
	log.Debug("auth ok", attrs...)
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
	}
	return h.Hijack()
}

func (w *statusWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *statusWriter) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		w.bytes += int(n)
		return n, err
	}
	n, err := io.Copy(writeFunc(func(p []byte) (int, error) {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		return w.ResponseWriter.Write(p)
	}), r)
	w.bytes += int(n)
	return n, err
}

type writeFunc func(p []byte) (int, error)

func (f writeFunc) Write(p []byte) (int, error) { return f(p) }

func AccessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if log == nil {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)

			status := sw.status
			if status == 0 {
				status = http.StatusOK
			}

			attrs := requestAttrs(r)
			attrs = append(attrs,
				"status", status,
				"duration_ms", time.Since(start).Milliseconds(),
				"bytes", sw.bytes,
			)
			if user := authctx.User(r.Context()); user != nil {
				attrs = append(attrs, "user", user.Email)
			}

			switch {
			case status >= 500:
				log.Error("request", attrs...)
			case status >= 400:
				log.Warn("request", attrs...)
			default:
				log.Info("request", attrs...)
			}
		})
	}
}
