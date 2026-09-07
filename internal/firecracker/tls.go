package firecracker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type Credentials struct {
	CA        []byte
	HostCert  []byte
	HostKey   []byte
	GuestCert []byte
	GuestKey  []byte
}

func CredentialsFor(id string) (Credentials, error) {
	var out Credentials
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return out, e
	}
	serial := func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120)); return n }
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "niflhel-" + id}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		return out, e
	}
	out.CA = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	leaf := func(cn string, usage x509.ExtKeyUsage) ([]byte, []byte, error) {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}, NotBefore: now.Add(-time.Hour), NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, e := x509.CreateCertificate(rand.Reader, cert, ca, &k.PublicKey, key)
		if e != nil {
			return nil, nil, e
		}
		raw, e := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw}), e
	}
	out.HostCert, out.HostKey, e = leaf("host", x509.ExtKeyUsageClientAuth)
	if e != nil {
		return out, e
	}
	out.GuestCert, out.GuestKey, e = leaf("guest-"+id, x509.ExtKeyUsageServerAuth)
	return out, e
}
func TLSConfig(ca, cert, key []byte, serverName string, server bool) (*tls.Config, error) {
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid CA")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: pool, ServerName: serverName}
	if server {
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
