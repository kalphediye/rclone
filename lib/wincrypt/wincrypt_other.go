//go:build !windows
// +build !windows

package wincrypt

import (
	"crypto/tls"
	"fmt"
)

type WINCRYPT struct {
}

func (*WINCRYPT) TLSCertificate() tls.Certificate {
	return tls.Certificate{}
}
func LoadWincrypt() (*WINCRYPT, error) {
	return nil, fmt.Errorf("CryptoAPI 2.0 is only available on Windows")
}
