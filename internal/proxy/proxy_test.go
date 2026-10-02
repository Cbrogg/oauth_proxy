package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatusCapturePreservesFlusher(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusCapture{ResponseWriter: rec}

	if _, ok := any(sw).(http.Flusher); !ok {
		t.Fatal("statusCapture must implement http.Flusher for streamable MCP responses")
	}
	sw.Flush()
}

func TestStatusCaptureReportsStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusCapture{ResponseWriter: rec}

	sw.WriteHeader(http.StatusServiceUnavailable)
	if sw.status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", sw.status, http.StatusServiceUnavailable)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("underlying code = %d", rec.Code)
	}
}

func TestStatusCaptureDefaultsToWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusCapture{ResponseWriter: rec}

	_, _ = sw.Write([]byte("ok"))
	if sw.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", sw.status, http.StatusOK)
	}
}

func TestStatusCaptureReadFromWithoutReaderFrom(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusCapture{ResponseWriter: rec}

	if _, ok := any(sw).(io.ReaderFrom); !ok {
		t.Fatal("statusCapture must implement io.ReaderFrom")
	}
	n, err := sw.ReadFrom(strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("n = %d, want 5", n)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("underlying code = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "hello" {
		t.Fatalf("body = %q, want hello", rec.Body.String())
	}
}

func TestStatusCaptureUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusCapture{ResponseWriter: rec}

	u, ok := any(sw).(interface{ Unwrap() http.ResponseWriter })
	if !ok {
		t.Fatal("statusCapture must expose Unwrap")
	}
	if u.Unwrap() != rec {
		t.Fatal("Unwrap did not return the underlying writer")
	}
}
