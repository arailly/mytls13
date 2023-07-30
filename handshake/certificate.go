package handshake

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/arailly/mytls13/util"
)

type certificate struct {
	length       util.Uint24
	certificates []innerCertificate
}

type innerCertificate struct {
	length      util.Uint24
	certificate []byte
}

func newCertificate(x509Certs []*x509.Certificate) *certificate {
	certs := make([]innerCertificate, 0, len(x509Certs))
	length := 0
	for _, cert := range x509Certs {
		certs = append(certs, innerCertificate{
			length:      util.NewUint24(uint32(len(cert.Raw))),
			certificate: cert.Raw,
		})
		length += 3 + len(cert.Raw)
	}
	return &certificate{
		length:       util.NewUint24(uint32(length)),
		certificates: certs,
	}
}

func parseCertificates(hs *handshake) ([]*x509.Certificate, error) {
	if hs.msgType != handshakeTypeCertificate {
		return nil, errors.New("invalid message type")
	}

	certMsg := hs.body[4:]
	certs := make([]*x509.Certificate, 0)
	offset := 0
	for {
		length := util.Uint24(certMsg[offset : offset+3])
		offset += 3
		certBytes := certMsg[offset : offset+length.Int()]
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		offset += length.Int()
		// skip extension
		offset += 2
		if offset >= len(certMsg) {
			break
		}
	}
	return certs, nil
}

func verifyCertificateSignature(
	cert *x509.Certificate,
	cacert *x509.Certificate,
) error {
	certHash := sha256.Sum256(cert.RawTBSCertificate)
	err := rsa.VerifyPKCS1v15(
		cacert.PublicKey.(*rsa.PublicKey),
		crypto.SHA256,
		certHash[:],
		cert.Signature,
	)
	return err
}

func verifyCertificateChain(
	serverName string,
	certs []*x509.Certificate,
	rootCAs []*x509.Certificate,
) error {
	if serverName != "" && serverName != certs[0].Subject.CommonName {
		return errors.New(
			"head of chain must be the server certificate",
		)
	}
	for _, cert := range certs {
		var issuerCert *x509.Certificate
		// verify by root CAs
		for _, cert_ := range rootCAs {
			if cert_.Subject.CommonName == cert.Issuer.CommonName {
				issuerCert = cert_
				break
			}
		}
		if issuerCert != nil {
			// check signature
			err := verifyCertificateSignature(cert, issuerCert)
			if err != nil {
				return err
			}
			// verified
			return nil
		}
		// find issuer in given cert chain
		for _, cert_ := range certs {
			if cert_.Subject.CommonName == cert.Issuer.CommonName {
				issuerCert = cert_
				break
			}
		}
		if issuerCert == nil {
			return errors.New("invalid chain")
		}
		// check signature
		err := verifyCertificateSignature(cert, issuerCert)
		if err != nil {
			return err
		}
	}
	return errors.New("not verified by root CAs")
}

func computeCertificateVerifyContent(hashed []byte) []byte {
	content := []byte{}
	for i := 0; i < 64; i++ {
		content = append(content, 0x20)
	}
	contextString := "TLS 1.3, server CertificateVerify"
	content = append(content, []byte(contextString)...)
	content = append(content, 0x00)
	content = append(content, hashed...)
	return content
}
