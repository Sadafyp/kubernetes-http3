// qlog_tracer.go
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quic-go/quic-go/logging"
	qlog "github.com/quic-go/quic-go/logging/qlog"
)

// newQLOGTracer returns a quic-go Tracer that writes one .sqlog per connection.
func newQLOGTracer(dir, prefix string) logging.Tracer {
	_ = os.MkdirAll(dir, 0o755)

	role := func(p logging.Perspective) string {
		if p == logging.PerspectiveClient {
			return "client"
		}
		return "server"
	}

	return qlog.NewTracer(func(p logging.Perspective, odcid logging.ConnectionID) io.WriteCloser {
		name := fmt.Sprintf("%s%s-%x-%s.sqlog",
			prefix, role(p), odcid, time.Now().UTC().Format("20060102-150405"))
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			return nopCloser{Writer: io.Discard} // fail-safe: don’t crash tracing
		}
		return f
	})
}

type nopCloser struct{ io.Writer }
func (nopCloser) Close() error { return nil }

// http3QLOGTracerFromEnv enables qlog when APISERVER_QLOG_DIR is set (non-empty).
// Optional: APISERVER_QLOG_PREFIX to add a filename prefix (e.g., RUN_ID).
func http3QLOGTracerFromEnv() logging.Tracer {
	dir := strings.TrimSpace(os.Getenv("APISERVER_QLOG_DIR"))
	if dir == "" {
		return nil
	}
	prefix := os.Getenv("APISERVER_QLOG_PREFIX") // optional; empty is fine
	return newQLOGTracer(dir, prefix)
}
