/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/trace"
	"golang.org/x/net/http2"
)

// Credentials are used to authenticate the client's connection to the server.
type Credentials struct {
	TLS *tls.Config
}

// CredentialsList is a list of credentials.
type CredentialsList []*Credentials

// CheckAndSetDefaults checks and sets default credential values.
func (cl CredentialsList) CheckAndSetDefaults() error {
	for _, c := range cl {
		if err := c.CheckAndSetDefaults(); err != nil {
			return err
		}
	}
	return nil
}

// CheckAndSetDefaults checks and sets default credential values.
func (c *Credentials) CheckAndSetDefaults() error {
	if c.TLS == nil {
		return trace.BadParameter("missing TLS config")
	}
	c.TLS = c.TLS.Clone()
	c.TLS.NextProtos = []string{http2.NextProtoTLS}
	if c.TLS.ServerName == "" {
		c.TLS.ServerName = constants.APIDomain
	}
	return nil
}

// LoadIdentityFile attempts to load credentials from the specified identity file's path.
// An identity file can be saved to disk by running `tsh login --out=identity_file_path`.
func LoadIdentityFile(path string) (*Credentials, error) {
	idf, err := ReadIdentityFile(path)
	if err != nil {
		return nil, trace.BadParameter("identity file could not be decoded: %v", err)
	}

	tls, err := idf.TLS()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return LoadTLS(tls), nil
}

// LoadKeyPair attempts to load credentials from the specified certificate paths.
// These certs can be generated with `tctl auth sign --out=path`.
// EX: path=/certs/admin creates three files - /certs/admin.(key|crt|cas).
func LoadKeyPair(certFile string, keyFile string, rootCAs string) (*Credentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	caCerts, err := ioutil.ReadFile(rootCAs)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caCerts); !ok {
		return nil, trace.Errorf("invalid TLS CA cert PEM")
	}

	return LoadTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}), nil
}

// LoadTLS returns Credentials with the given TLS config.
func LoadTLS(tls *tls.Config) *Credentials {
	return &Credentials{TLS: tls}
}