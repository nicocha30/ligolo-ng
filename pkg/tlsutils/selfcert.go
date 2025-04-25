// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package tlsutils

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"math/big"
	"sync"
	"time"
)

type SelfCert struct {
	certificateMap   map[string]*tls.Certificate
	certificateMutex sync.Mutex
	cache            *autocert.DirCache
}

func NewSelfCert(cache *autocert.DirCache) *SelfCert {
	return &SelfCert{cache: cache, certificateMap: make(map[string]*tls.Certificate)}
}

func (c *SelfCert) GetCertificate(servername string) (*tls.Certificate, error) {
	// Check memory cache
	c.certificateMutex.Lock()
	if cert, ok := c.certificateMap[servername]; ok {
		c.certificateMutex.Unlock()
		return cert, nil
	}
	c.certificateMutex.Unlock()
	// Not in memory cache, check in disk cache...
	if c.cache != nil {
		certBytes, err := c.cache.Get(context.Background(), fmt.Sprintf("%s_cert", servername))
		if err == nil {
			// No error, attempt to decode cert...
			privBytes, err := c.cache.Get(context.Background(), fmt.Sprintf("%s_key", servername))
			if err != nil {
				return nil, err
			}

			block, _ := pem.Decode(privBytes)

			privateKey, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}

			blockPub, _ := pem.Decode(certBytes)
			blockCertBytes := blockPub.Bytes

			finalCert := &tls.Certificate{
				Certificate: [][]byte{blockCertBytes},
				PrivateKey:  privateKey,
			}
			// Cache in memory!
			c.certificateMutex.Lock()
			c.certificateMap[servername] = finalCert
			c.certificateMutex.Unlock()

			return finalCert, nil
		} else {
			logrus.Errorf("Certificate cache error: %v, returning a new certificate\n", err)
		}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{servername},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if servername != "" {
		template.DNSNames = []string{servername}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	if err != nil {
		return nil, err
	}
	finalCert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	x509Encoded, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	if err := pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: x509Encoded,
	}); err != nil {
		return nil, err
	}
	// Cache in disk!
	if c.cache != nil {
		c.cache.Put(context.Background(), fmt.Sprintf("%s_cert", servername), certPEM.Bytes())
		c.cache.Put(context.Background(), fmt.Sprintf("%s_key", servername), certPrivKeyPEM.Bytes())
	}
	// Cache in memory!
	c.certificateMutex.Lock()
	c.certificateMap[servername] = finalCert
	c.certificateMutex.Unlock()
	return finalCert, nil
}
