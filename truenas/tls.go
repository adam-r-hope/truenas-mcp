package truenas

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// NewTLSConfig returns the TLS configuration for connecting to TrueNAS.
//
// By default the server certificate is fully verified (chain and hostname)
// against the system trust store. caPath, if non-empty, names a PEM file
// whose certificates are trusted instead - typically the TrueNAS server's
// own self-signed certificate, or a private CA. insecure disables
// verification entirely and must remain an explicit opt-in: it leaves the
// connection open to man-in-the-middle interception.
func NewTLSConfig(insecure bool, caPath string) (*tls.Config, error) {
	if insecure {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	if caPath == "" {
		return &tls.Config{}, nil
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates found in %s", caPath)
	}
	return &tls.Config{RootCAs: pool}, nil
}
