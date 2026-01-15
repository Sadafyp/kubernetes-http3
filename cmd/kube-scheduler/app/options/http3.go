package options

import (
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	rest "k8s.io/client-go/rest"
	clienttransport "k8s.io/client-go/transport"
	"k8s.io/klog/v2"
)

// switches client-go transport to HTTP/3 with WrapTransport
// cfg.Transport doesn't work, client-go rejects that when TLS options are also set
// force=false => prefer H3, fallback to the original (HTTP/2) transport on error
// force=true  => H3 only (no fallback)
func ApplyHTTP3ToRestConfig(cfg *rest.Config, force bool) {
	cfg.WrapTransport = func(base http.RoundTripper) http.RoundTripper {
		// Building tls . Config from the same rest . Config TLS stack
		tlsCfg, err := clienttransport.TLSConfigFor(&clienttransport.Config{
			TLS: clienttransport.TLSConfig{
				Insecure:   cfg.TLSClientConfig.Insecure,
				CAFile:     cfg.TLSClientConfig.CAFile,
				CAData:     cfg.TLSClientConfig.CAData,
				CertFile:   cfg.TLSClientConfig.CertFile,
				CertData:   cfg.TLSClientConfig.CertData,
				KeyFile:    cfg.TLSClientConfig.KeyFile,
				KeyData:    cfg.TLSClientConfig.KeyData,
				ServerName: cfg.TLSClientConfig.ServerName,
				// setting ALPN h3
				NextProtos: []string{"h3"},
			},
		})
		if err != nil {
			// TLS for H3 doesn't work, keep the original (HTTP/2)
			klog.ErrorS(err, "Failed to build TLS config for HTTP/3; falling back to base transport (HTTP/2)")
			return base
		}

		h3rt := &http3.RoundTripper{
			TLSClientConfig: tlsCfg,
			QUICConfig:      &quic.Config{},
			// EnableDatagrams: false,
		}

		if force {
			klog.Info("HTTP/3 strict mode: using H3 only (no fallback)")
			return h3rt
		}

		klog.Info("HTTP/3 auto mode: prefer H3, fallback to HTTP/2 on error")
		return &preferH3{h3: h3rt, h2: base}
	}
}

type preferH3 struct {
	h3 http.RoundTripper
	h2 http.RoundTripper
}

func (p *preferH3) RoundTrip(req *http.Request) (*http.Response, error) {
	if resp, err := p.h3.RoundTrip(req); err == nil {
		return resp, nil
	}
	return p.h2.RoundTrip(req)
}
