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

package test

import (
	"crypto/rsa"
	"crypto/x509/pkix"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/jwt"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"

	"github.com/jonboulle/clockwork"
)

// NewTestCA returns new test authority with a test key as a public and
// signing key
func NewTestCA(caType services.CertAuthType, clusterName string, privateKeys ...[]byte) *services.CertAuthorityV2 {
	return NewTestCAWithConfig(TestCAConfig{
		Type:        caType,
		ClusterName: clusterName,
		PrivateKeys: privateKeys,
		Clock:       clockwork.NewRealClock(),
	})
}

// TestCAConfig defines the configuration for generating
// a test certificate authority
type TestCAConfig struct {
	Type        services.CertAuthType
	ClusterName string
	PrivateKeys [][]byte
	Clock       clockwork.Clock
}

// NewTestCAWithConfig generates a new certificate authority with the specified
// configuration
func NewTestCAWithConfig(config TestCAConfig) *types.CertAuthorityV2 {
	// privateKeys is to specify another RSA private key
	if len(config.PrivateKeys) == 0 {
		config.PrivateKeys = [][]byte{fixtures.PEMBytes["rsa"]}
	}
	keyBytes := config.PrivateKeys[0]
	rsaKey, err := ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		panic(err)
	}

	signer, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		panic(err)
	}

	key, cert, err := tlsca.GenerateSelfSignedCAWithConfig(tlsca.GenerateCAConfig{
		PrivateKey: rsaKey.(*rsa.PrivateKey),
		Entity: pkix.Name{
			CommonName:   config.ClusterName,
			Organization: []string{config.ClusterName},
		},
		TTL:   defaults.CATTL,
		Clock: config.Clock,
	})
	if err != nil {
		panic(err)
	}

	publicKey, privateKey, err := jwt.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	return &types.CertAuthorityV2{
		Kind:    types.KindCertAuthority,
		SubKind: string(config.Type),
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      config.ClusterName,
			Namespace: defaults.Namespace,
		},
		Spec: types.CertAuthoritySpecV2{
			Type:         config.Type,
			ClusterName:  config.ClusterName,
			CheckingKeys: [][]byte{ssh.MarshalAuthorizedKey(signer.PublicKey())},
			SigningKeys:  [][]byte{keyBytes},
			TLSKeyPairs:  []types.TLSKeyPair{{Cert: cert, Key: key}},
			JWTKeyPairs: []types.JWTKeyPair{
				{
					PublicKey:  publicKey,
					PrivateKey: privateKey,
				},
			},
		},
	}
}
