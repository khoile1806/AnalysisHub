package handlers

import (
	"crypto/tls"
	"os"
	"strings"
)

// siemTLSConfig returns the TLS config used for outbound connections to operator-
// configured SIEM/TI backends (ELK, OpenCTI, QRadar, Splunk). These are commonly
// deployed with self-signed certificates, so certificate verification is DISABLED
// by default to preserve out-of-the-box connectivity (unchanged behaviour).
//
// Set SIEM_TLS_VERIFY=true to opt into strict certificate verification for
// deployments whose SIEM presents a trusted certificate.
func siemTLSConfig() *tls.Config {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("SIEM_TLS_VERIFY")), "true") {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in strict via SIEM_TLS_VERIFY; SIEMs commonly use self-signed certs
}
