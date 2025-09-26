package app

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"k8s.io/klog/v2"
)

// newHTTP3Client builds a *http.Client that talks HTTP/3 (QUIC) using the
// same TLS as a normal client-go *rest.Config
func newHTTP3Client(
	cfg *rest.Config,
	getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error),
) (*http.Client, func(), error){
	if cfg == nil {
		return nil, nil, fmt.Errorf("http3: nil rest.Config")
	}

	// Convert kube rest.Config.TLSClientConfig to *tls.Config via client-go helpers.
	tcfg := &transport.Config{
		TLS: transport.TLSConfig{
			CAFile:     cfg.TLSClientConfig.CAFile,
			CAData:     cfg.TLSClientConfig.CAData,
			CertFile:   cfg.TLSClientConfig.CertFile,
			CertData:   cfg.TLSClientConfig.CertData,
			KeyFile:    cfg.TLSClientConfig.KeyFile,
			KeyData:    cfg.TLSClientConfig.KeyData,
			ServerName: cfg.TLSClientConfig.ServerName,
			Insecure:   cfg.TLSClientConfig.Insecure,
		},
	}

	tlsCfg, err := transport.TLSConfigFor(tcfg)
	if err != nil {
		return nil, nil, fmt.Errorf("http3: TLSConfigFor: %w", err)
	}
	// works if TLSConfigFor returns nil (in case no TLS input is set)
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}

	// HTTP/3 requires TLS 1.3 and ALPN "h3"
	if tlsCfg.MinVersion < tls.VersionTLS13 {
		tlsCfg.MinVersion = tls.VersionTLS13
	}
	
	//When rotation is enabled, fetches the current cert from the kubelet’s certificate manager
	if getClientCert != nil {
		tlsCfg.GetClientCertificate = getClientCert
	}
	http3.ConfigureTLSConfig(tlsCfg)

	// QUIC tuning (safe defaults)
	quicCfg := &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      10 * time.Second,
	}

	rt := &http3.RoundTripper{
		TLSClientConfig: tlsCfg,
		QUICConfig:      quicCfg,
	}

	klog.InfoS("http3: kubelet HTTP/3 transport initialized")
	closeFn := func() { _ = rt.Close() }
	return &http.Client{Transport: rt}, closeFn, nil
}

