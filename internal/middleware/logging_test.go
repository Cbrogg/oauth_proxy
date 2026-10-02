package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatusWriterPreservesFlusher(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}

	if _, ok := any(sw).(http.Flusher); !ok {
		t.Fatal("statusWriter must implement http.Flusher for streamable MCP responses")
	}
	sw.Flush()
}

func TestStatusWriterUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}

	u, ok := any(sw).(interface{ Unwrap() http.ResponseWriter })
	if !ok {
		t.Fatal("statusWriter must expose Unwrap")
	}
	if u.Unwrap() != rec {
		t.Fatal("Unwrap did not return the underlying writer")
	}
}

func TestStatusWriterReadFromCountsBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}

	if _, ok := any(sw).(io.ReaderFrom); !ok {
		t.Fatal("statusWriter must implement io.ReaderFrom")
	}
	n, err := sw.ReadFrom(strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("n = %d, want 5", n)
	}
	if sw.bytes != 5 {
		t.Fatalf("bytes = %d, want 5", sw.bytes)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("underlying code = %d", rec.Code)
	}
}

func TestStatusWriterThroughAccessLogStreams(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("handler must receive an http.Flusher through the access log wrapper")
		}
		_, _ = w.Write([]byte("chunk"))
		f.Flush()
		called = true
	})

	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec := httptest.NewRecorder()
	logged := AccessLog(discard)(inner)
	logged.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if !called {
		t.Fatal("inner handler was not invoked")
	}
	if rec.Body.String() != "chunk" {
		t.Fatalf("body = %q, want chunk", rec.Body.String())
	}
}
