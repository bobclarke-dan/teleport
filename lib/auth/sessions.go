/*
Copyright 2020 Gravitational, Inc.

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

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/jwt"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"

	"github.com/pborman/uuid"
)

// CreateAppSession creates and inserts a types.WebSession into the
// backend with the identity of the caller used to generate the certificate.
// The certificate is used for all access requests, which is where access
// control is enforced.
func (s *Server) CreateAppSession(ctx context.Context, req types.CreateAppSessionRequest, user types.User, checker AccessChecker) (types.WebSession, error) {
	// Check that a matching parent web session exists in the backend.
	parentSession, err := s.Services.GetWebSession(ctx, types.GetWebSessionRequest{
		User:      req.Username,
		SessionID: req.ParentSession,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Don't let the TTL of the child certificate go longer than the parent.
	ttl := checker.AdjustSessionTTL(parentSession.GetExpiryTime().Sub(s.clock.Now()))

	// Create certificate for this session.
	privateKey, publicKey, err := s.GetNewKeyPairFromPool()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certs, err := s.generateUserCert(certRequest{
		user:      user,
		publicKey: publicKey,
		checker:   checker,
		ttl:       ttl,
		// Set the login to be a random string. Application certificates are never
		// used to log into servers but SSH certificate generation code requires a
		// principal be in the certificate.
		traits: wrappers.Traits(map[string][]string{
			teleport.TraitLogins: {uuid.New()},
		}),
		// Only allow this certificate to be used for applications.
		usage: []string{teleport.UsageAppsOnly},
		// Add in the application routing information.
		appSessionID:   uuid.New(),
		appPublicAddr:  req.PublicAddr,
		appClusterName: req.ClusterName,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create types.WebSession for this session.
	sessionID, err := utils.CryptoRandomHex(SessionTokenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	session := types.NewWebSession(sessionID, types.KindWebSession, types.KindAppSession, types.WebSessionSpecV2{
		User:    req.Username,
		Priv:    privateKey,
		Pub:     certs.ssh,
		TLSCert: certs.tls,
		Expires: s.clock.Now().Add(ttl),
	})
	if err = s.Services.ServerIdentity.UpsertAppSession(ctx, session); err != nil {
		return nil, trace.Wrap(err)
	}
	log.Debugf("Generated application web session for %v with TTL %v.", req.Username, ttl)

	return session, nil
}

// generateAppToken generates an JWT token that will be passed along with every
// application request.
func (s *Server) generateAppToken(username string, roles []string, uri string, expires time.Time) (string, error) {
	// Get the clusters CA.
	clusterName, err := s.GetDomainName()
	if err != nil {
		return "", trace.Wrap(err)
	}
	ca, err := s.GetCertAuthority(types.CertAuthID{
		Type:       types.JWTSigner,
		DomainName: clusterName,
	}, true)
	if err != nil {
		return "", trace.Wrap(err)
	}

	// Extract the JWT signing key and sign the claims.
	privateKey, err := GetJWTSigner(ca, s.clock)
	if err != nil {
		return "", trace.Wrap(err)
	}
	token, err := privateKey.Sign(jwt.SignParams{
		Username: username,
		Roles:    roles,
		URI:      uri,
		Expires:  expires,
	})
	if err != nil {
		return "", trace.Wrap(err)
	}

	return token, nil
}

// WebSessionSpecV2Schema is JSON schema for cert authority V2
const WebSessionSpecV2Schema = `{
	"type": "object",
	"additionalProperties": false,
	"required": ["pub", "bearer_token", "bearer_token_expires", "expires", "user"],
	"properties": {
	  "user": {"type": "string"},
	  "pub": {"type": "string"},
	  "priv": {"type": "string"},
	  "tls_cert": {"type": "string"},
	  "bearer_token": {"type": "string"},
	  "bearer_token_expires": {"type": "string"},
	  "expires": {"type": "string"}%v
	}
  }`

// GetWebSessionSchema returns JSON Schema for web session
func GetWebSessionSchema() string {
	return GetWebSessionSchemaWithExtensions("")
}

// GetWebSessionSchemaWithExtensions returns JSON Schema for web session with user-supplied extensions
func GetWebSessionSchemaWithExtensions(extension string) string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, fmt.Sprintf(WebSessionSpecV2Schema, extension), DefaultDefinitions)
}

// ExtendWebSession renews web session and is used to
// inject additional data in extenstions when session is getting renewed
func ExtendWebSession(ws WebSession) (WebSession, error) {
	return ws, nil
}

// UnmarshalWebSession unmarshals the WebSession resource from JSON.
func UnmarshalWebSession(bytes []byte, opts ...MarshalOption) (types.WebSession, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var h ResourceHeader
	err = json.Unmarshal(bytes, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch h.Version {
	case V2:
		var ws types.WebSessionV2
		if err := utils.UnmarshalWithSchema(GetWebSessionSchema(), &ws, bytes); err != nil {
			return nil, trace.BadParameter(err.Error())
		}
		utils.UTC(&ws.Spec.BearerTokenExpires)
		utils.UTC(&ws.Spec.Expires)

		if err := ws.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		if cfg.ID != 0 {
			ws.SetResourceID(cfg.ID)
		}
		if !cfg.Expires.IsZero() {
			ws.SetExpiry(cfg.Expires)
		}

		return &ws, nil
	}

	return nil, trace.BadParameter("web session resource version %v is not supported", h.Version)
}

// MarshalWebSession marshals the WebSession resource to JSON.
func MarshalWebSession(ws types.WebSession, opts ...MarshalOption) ([]byte, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch webSession := ws.(type) {
	case *WebSessionV2:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *webSession
			copy.SetResourceID(0)
			webSession = &copy
		}
		return utils.FastMarshal(webSession)
	default:
		return nil, trace.BadParameter("unrecognized web session version %T", ws)
	}
}

// MarshalWebToken serializes the web token as JSON-encoded payload
func MarshalWebToken(token types.WebToken, opts ...MarshalOption) ([]byte, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	version := cfg.GetVersion()
	switch version {
	case V3:
		value, ok := token.(*types.WebTokenV3)
		if !ok {
			return nil, trace.BadParameter("don't know how to marshal web token %v", token)
		}
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *value
			copy.SetResourceID(0)
			value = &copy
		}
		return utils.FastMarshal(value)
	default:
		return nil, trace.BadParameter("version %v is not supported", version)
	}
}

// UnmarshalWebToken interprets bytes as JSON-encoded web token value
func UnmarshalWebToken(bytes []byte, opts ...MarshalOption) (types.WebToken, error) {
	config, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var hdr ResourceHeader
	err = json.Unmarshal(bytes, &hdr)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch hdr.Version {
	case V3:
		var token types.WebTokenV3
		if err := utils.UnmarshalWithSchema(GetWebTokenSchema(), &token, bytes); err != nil {
			return nil, trace.BadParameter("invalid web token: %v", err.Error())
		}
		if err := token.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		if config.ID != 0 {
			token.SetResourceID(config.ID)
		}
		if !config.Expires.IsZero() {
			token.Metadata.SetExpiry(config.Expires)
		}
		utils.UTC(token.Metadata.Expires)
		return &token, nil
	}
	return nil, trace.BadParameter("web token resource version %v is not supported", hdr.Version)
}

// GetWebTokenSchema returns JSON schema for the web token resource
func GetWebTokenSchema() string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, WebTokenSpecV3Schema, "")
}

// WebTokenSpecV3Schema is JSON schema for the web token V3
const WebTokenSpecV3Schema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["token", "user"],
  "properties": {
    "user": {"type": "string"},
    "token": {"type": "string"}
  }
}`
