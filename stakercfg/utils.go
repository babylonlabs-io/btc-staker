package stakercfg

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// ReadCertFile reads a certificate from a raw hex string or file path.
func ReadCertFile(rawCert string, certFilePath string) ([]byte, error) {
	if rawCert != "" {
		rpcCert, err := hex.DecodeString(rawCert)
		if err != nil {
			return nil, err
		}
		return rpcCert, nil
	}
	certFile, err := os.Open(certFilePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := certFile.Close(); err != nil {
			fmt.Printf("failed to close cert file: %v\n", err)
		}
	}()

	rpcCert, err := io.ReadAll(certFile)
	if err != nil {
		return nil, err
	}

	return rpcCert, nil
}
