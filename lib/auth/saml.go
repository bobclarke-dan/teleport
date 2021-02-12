/*
Copyright 2019 Gravitational, Inc.

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
	"bytes"
	"compress/flate"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/jonboulle/clockwork"

	"github.com/beevik/etree"
	"github.com/gravitational/trace"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

// UpsertSAMLConnector creates or updates a SAML connector.
func (a *Server) UpsertSAMLConnector(ctx context.Context, connector types.SAMLConnector) error {
	if err := a.Services.ServerIdentity.UpsertSAMLConnector(connector); err != nil {
		return trace.Wrap(err)
	}
	if err := a.emitter.EmitAuditEvent(ctx, &events.OIDCConnectorCreate{
		Metadata: events.Metadata{
			Type: events.SAMLConnectorCreatedEvent,
			Code: events.SAMLConnectorCreatedCode,
		},
		UserMetadata: events.UserMetadata{
			User: clientUsername(ctx),
		},
		ResourceMetadata: events.ResourceMetadata{
			Name: connector.GetName(),
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit SAML connector create event.")
	}

	return nil
}

// DeleteSAMLConnector deletes a SAML connector by name.
func (a *Server) DeleteSAMLConnector(ctx context.Context, connectorName string) error {
	if err := a.Services.ServerIdentity.DeleteSAMLConnector(connectorName); err != nil {
		return trace.Wrap(err)
	}
	if err := a.emitter.EmitAuditEvent(ctx, &events.OIDCConnectorDelete{
		Metadata: events.Metadata{
			Type: events.SAMLConnectorDeletedEvent,
			Code: events.SAMLConnectorDeletedCode,
		},
		UserMetadata: events.UserMetadata{
			User: clientUsername(ctx),
		},
		ResourceMetadata: events.ResourceMetadata{
			Name: connectorName,
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit SAML connector delete event.")
	}

	return nil
}

func (a *Server) CreateSAMLAuthRequest(req services.SAMLAuthRequest) (*services.SAMLAuthRequest, error) {
	connector, err := a.Services.ServerIdentity.GetSAMLConnector(req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	provider, err := a.getSAMLProvider(connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	doc, err := provider.BuildAuthRequestDocument()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	attr := doc.Root().SelectAttr("ID")
	if attr == nil || attr.Value == "" {
		return nil, trace.BadParameter("missing auth request ID")
	}

	req.ID = attr.Value
	req.RedirectURL, err = provider.BuildAuthURLFromDocument("", doc)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = a.Services.ServerIdentity.CreateSAMLAuthRequest(req, defaults.SAMLAuthRequestTTL)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &req, nil
}

func (a *Server) getSAMLProvider(conn types.SAMLConnector) (*saml2.SAMLServiceProvider, error) {
	a.lock.Lock()
	defer a.lock.Unlock()

	providerPack, ok := a.samlProviders[conn.GetName()]
	if ok && providerPack.connector.Equals(conn) {
		return providerPack.provider, nil
	}
	delete(a.samlProviders, conn.GetName())

	serviceProvider, err := services.GetSAMLServiceProvider(conn, a.clock)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	a.samlProviders[conn.GetName()] = &samlProvider{connector: conn, provider: serviceProvider}

	return serviceProvider, nil
}

func (a *Server) calculateSAMLUser(connector types.SAMLConnector, assertionInfo saml2.AssertionInfo, request *services.SAMLAuthRequest) (*createUserParams, error) {
	var err error

	p := createUserParams{
		connectorName: connector.GetName(),
		username:      assertionInfo.NameID,
	}

	p.traits = services.SAMLAssertionsToTraits(assertionInfo)

	p.roles = services.TraitsToRoles(connector.GetTraitMappings(), p.traits)
	if len(p.roles) == 0 {
		return nil, trace.AccessDenied("unable to map attributes to role for connector: %v", connector.GetName())
	}

	// Pick smaller for role: session TTL from role or requested TTL.
	roles, err := FetchRoles(p.roles, a.Services.ServerAccess, p.traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleTTL := roles.AdjustSessionTTL(defaults.MaxCertDuration)
	p.sessionTTL = utils.MinTTL(roleTTL, request.CertTTL)

	return &p, nil
}

func (a *Server) createSAMLUser(p *createUserParams) (types.User, error) {
	expires := a.GetClock().Now().UTC().Add(p.sessionTTL)

	log.Debugf("Generating dynamic SAML identity %v/%v with roles: %v.", p.connectorName, p.username, p.roles)

	user := &types.UserV2{
		Kind:    types.KindUser,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      p.username,
			Namespace: defaults.Namespace,
			Expires:   &expires,
		},
		Spec: types.UserSpecV2{
			Roles:  p.roles,
			Traits: p.traits,
			SAMLIdentities: []types.ExternalIdentity{
				{
					ConnectorID: p.connectorName,
					Username:    p.username,
				},
			},
			CreatedBy: types.CreatedBy{
				User: types.UserRef{
					Name: teleport.UserSystem,
				},
				Time: a.clock.Now().UTC(),
				Connector: &types.ConnectorRef{
					Type:     teleport.SAML,
					ID:       p.connectorName,
					Identity: p.username,
				},
			},
		},
	}

	// Get the user to check if it already exists or not.
	existingUser, err := a.Services.ServerIdentity.GetUser(p.username, false)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	ctx := context.TODO()

	// Overwrite exisiting user if it was created from an external identity provider.
	if existingUser != nil {
		connectorRef := existingUser.GetCreatedBy().Connector

		// If the exisiting user is a local user, fail and advise how to fix the problem.
		if connectorRef == nil {
			return nil, trace.AlreadyExists("local user with name %q already exists. Either change "+
				"NameID in assertion or remove local user and try again.", existingUser.GetName())
		}

		log.Debugf("Overwriting existing user %q created with %v connector %v.",
			existingUser.GetName(), connectorRef.Type, connectorRef.ID)

		if err := a.UpdateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if err := a.CreateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return user, nil
}

func parseSAMLInResponseTo(response string) (string, error) {
	raw, _ := base64.StdEncoding.DecodeString(response)

	doc := etree.NewDocument()
	err := doc.ReadFromBytes(raw)
	if err != nil {
		// Attempt to inflate the response in case it happens to be compressed (as with one case at saml.oktadev.com)
		buf, err := ioutil.ReadAll(flate.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return "", trace.Wrap(err)
		}

		doc = etree.NewDocument()
		err = doc.ReadFromBytes(buf)
		if err != nil {
			return "", trace.Wrap(err)
		}
	}

	if doc.Root() == nil {
		return "", trace.BadParameter("unable to parse response")
	}

	// teleport only supports sending party initiated flows (Teleport sends an
	// AuthnRequest to the IdP and gets a SAMLResponse from the IdP). identity
	// provider initiated flows (where Teleport gets an unsolicited SAMLResponse
	// from the IdP) are not supported.
	el := doc.Root()
	responseTo := el.SelectAttr("InResponseTo")
	if responseTo == nil {
		message := "teleport does not support initiating login from a SAML identity provider, login must be initiated from either the Teleport Web UI or CLI"
		log.Infof(message)
		return "", trace.NotImplemented(message)
	}
	if responseTo.Value == "" {
		return "", trace.BadParameter("InResponseTo can not be empty")
	}
	return responseTo.Value, nil
}

// SAMLAuthResponse is returned when auth server validated callback parameters
// returned from SAML identity provider
type SAMLAuthResponse struct {
	// Username is an authenticated teleport username
	Username string `json:"username"`
	// Identity contains validated SAML identity
	Identity types.ExternalIdentity `json:"identity"`
	// Web session will be generated by auth server if requested in SAMLAuthRequest
	Session types.WebSession `json:"session,omitempty"`
	// Cert will be generated by certificate authority
	Cert []byte `json:"cert,omitempty"`
	// TLSCert is a PEM encoded TLS certificate
	TLSCert []byte `json:"tls_cert,omitempty"`
	// Req is an original SAML auth request
	Req services.SAMLAuthRequest `json:"req"`
	// HostSigners is a list of signing host public keys
	// trusted by proxy, used in console login
	HostSigners []types.CertAuthority `json:"host_signers"`
}

// ValidateSAMLResponse consumes attribute statements from SAML identity provider
func (a *Server) ValidateSAMLResponse(samlResponse string) (*SAMLAuthResponse, error) {
	event := &events.UserLogin{
		Metadata: events.Metadata{
			Type: events.UserLoginEvent,
		},
		Method: events.LoginMethodSAML,
	}
	re, err := a.validateSAMLResponse(samlResponse)
	if re != nil && re.attributeStatements != nil {
		attributes, err := events.EncodeMapStrings(re.attributeStatements)
		if err != nil {
			log.WithError(err).Warn("Failed to encode identity attributes.")
		} else {
			event.IdentityAttributes = attributes
		}
	}
	if err != nil {
		event.Code = events.UserSSOLoginFailureCode
		event.Status.Success = false
		event.Status.Error = trace.Unwrap(err).Error()
		event.Status.UserMessage = err.Error()
		if err := a.emitter.EmitAuditEvent(a.closeCtx, event); err != nil {
			log.WithError(err).Warn("Failed to emit SAML login success event.")
		}
		return nil, trace.Wrap(err)
	}
	event.Status.Success = true
	event.User = re.auth.Username
	event.Code = events.UserSSOLoginCode
	if err := a.emitter.EmitAuditEvent(a.closeCtx, event); err != nil {
		log.WithError(err).Warn("Failed to emit SAML login failure event.")
	}
	return &re.auth, nil
}

type samlAuthResponse struct {
	auth                SAMLAuthResponse
	attributeStatements map[string][]string
}

func (a *Server) validateSAMLResponse(samlResponse string) (*samlAuthResponse, error) {
	requestID, err := parseSAMLInResponseTo(samlResponse)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	request, err := a.Services.ServerIdentity.GetSAMLAuthRequest(requestID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	connector, err := a.Services.ServerIdentity.GetSAMLConnector(request.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	provider, err := a.getSAMLProvider(connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	assertionInfo, err := provider.RetrieveAssertionInfo(samlResponse)
	if err != nil {
		return nil, trace.AccessDenied(
			"received response with incorrect or missing attribute statements, please check the identity provider configuration to make sure that mappings for claims/attribute statements are set up correctly. <See: https://goteleport.com/teleport/docs/enterprise/sso/ssh-sso/>, failed to retrieve SAML assertion info from response: %v.", err)
	}

	if assertionInfo.WarningInfo.InvalidTime {
		return nil, trace.AccessDenied("invalid time in SAML assertion info")
	}

	if assertionInfo.WarningInfo.NotInAudience {
		return nil, trace.AccessDenied("no audience in SAML assertion info")
	}

	log.Debugf("Obtained SAML assertions for %q.", assertionInfo.NameID)
	re := &samlAuthResponse{
		attributeStatements: make(map[string][]string),
	}
	for key, val := range assertionInfo.Values {
		var vals []string
		for _, vv := range val.Values {
			vals = append(vals, vv.Value)
		}
		log.Debugf("SAML assertion: %q: %q.", key, vals)
		re.attributeStatements[key] = vals
	}

	log.Debugf("SAML assertion warnings: %+v.", assertionInfo.WarningInfo)

	if len(connector.GetAttributesToRoles()) == 0 {
		return re, trace.BadParameter("no attributes to roles mapping, check connector documentation")
	}
	log.Debugf("Applying %v SAML attribute to roles mappings.", len(connector.GetAttributesToRoles()))

	// Calculate (figure out name, roles, traits, session TTL) of user and
	// create the user in the backend.
	params, err := a.calculateSAMLUser(connector, *assertionInfo, request)
	if err != nil {
		return re, trace.Wrap(err)
	}
	user, err := a.createSAMLUser(params)
	if err != nil {
		return re, trace.Wrap(err)
	}

	// Auth was successful, return session, certificate, etc. to caller.
	re.auth = SAMLAuthResponse{
		Req: *request,
		Identity: types.ExternalIdentity{
			ConnectorID: params.connectorName,
			Username:    params.username,
		},
		Username: user.GetName(),
	}

	// If the request is coming from a browser, create a web session.
	if request.CreateWebSession {
		session, err := a.createWebSession(context.TODO(), types.NewWebSessionRequest{
			User:       user.GetName(),
			Roles:      user.GetRoles(),
			Traits:     user.GetTraits(),
			SessionTTL: params.sessionTTL,
		})
		if err != nil {
			return re, trace.Wrap(err)
		}

		re.auth.Session = session
	}

	// If a public key was provided, sign it and return a certificate.
	if len(request.PublicKey) != 0 {
		sshCert, tlsCert, err := a.createSessionCert(user, params.sessionTTL, request.PublicKey, request.Compatibility, request.RouteToCluster, request.KubernetesCluster)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		clusterName, err := a.GetClusterName()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		re.auth.Cert = sshCert
		re.auth.TLSCert = tlsCert

		// Return the host CA for this cluster only.
		authority, err := a.GetCertAuthority(types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		re.auth.HostSigners = append(re.auth.HostSigners, authority)
	}

	return re, nil
}

// ValidateSAMLConnector validates the SAMLConnector and sets default values
func ValidateSAMLConnector(sc SAMLConnector) error {
	if err := sc.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	if sc.GetEntityDescriptorURL() != "" {
		resp, err := http.Get(sc.GetEntityDescriptorURL())
		if err != nil {
			return trace.Wrap(err)
		}
		if resp.StatusCode != http.StatusOK {
			return trace.BadParameter("status code %v when fetching from %q", resp.StatusCode, sc.GetEntityDescriptorURL())
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return trace.Wrap(err)
		}
		sc.SetEntityDescriptor(string(body))
		log.Debugf("[SAML] Successfully fetched entity descriptor from %q", sc.GetEntityDescriptorURL())
	}

	if sc.GetEntityDescriptor() != "" {
		metadata := &types.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(sc.GetEntityDescriptor()), metadata); err != nil {
			return trace.Wrap(err, "failed to parse entity_descriptor")
		}

		sc.SetIssuer(metadata.EntityID)
		if len(metadata.IDPSSODescriptor.SingleSignOnServices) > 0 {
			sc.SetSSO(metadata.IDPSSODescriptor.SingleSignOnServices[0].Location)
		}
	}

	if sc.GetIssuer() == "" {
		return trace.BadParameter("no issuer or entityID set, either set issuer as a parameter or via entity_descriptor spec")
	}
	if sc.GetSSO() == "" {
		return trace.BadParameter("no SSO set either explicitly or via entity_descriptor spec")
	}

	if sc.GetSigningKeyPair() == nil {
		keyPEM, certPEM, err := utils.GenerateSelfSignedSigningCert(pkix.Name{
			Organization: []string{"Teleport OSS"},
			CommonName:   "teleport.localhost.localdomain",
		}, nil, 10*365*24*time.Hour)
		if err != nil {
			return trace.Wrap(err)
		}
		sc.SetSigningKeyPair(&SigningKeyPair{
			PrivateKey: string(keyPEM),
			Cert:       string(certPEM),
		})
	}

	log.Debugf("[SAML] SSO: %v", sc.GetSSO())
	log.Debugf("[SAML] Issuer: %v", sc.GetIssuer())
	log.Debugf("[SAML] ACS: %v", sc.GetAssertionConsumerService())

	return nil
}

// GetAttributeNames returns a list of claim names from the claim values
func GetAttributeNames(attributes map[string]types.Attribute) []string {
	var out []string
	for _, attr := range attributes {
		out = append(out, attr.Name)
	}
	return out
}

// SAMLAssertionsToTraits converts saml assertions to traits
func SAMLAssertionsToTraits(assertions saml2.AssertionInfo) map[string][]string {
	traits := make(map[string][]string, len(assertions.Values))
	for _, assr := range assertions.Values {
		vals := make([]string, 0, len(assr.Values))
		for _, value := range assr.Values {
			vals = append(vals, value.Value)
		}
		traits[assr.Name] = vals
	}
	return traits
}

// GetSAMLServiceProvider gets the SAMLConnector's service provider
func GetSAMLServiceProvider(sc SAMLConnector, clock clockwork.Clock) (*saml2.SAMLServiceProvider, error) {
	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	if sc.GetEntityDescriptor() != "" {
		metadata := &types.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(sc.GetEntityDescriptor()), metadata); err != nil {
			return nil, trace.Wrap(err, "failed to parse entity_descriptor")
		}

		for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
			for _, samlCert := range kd.KeyInfo.X509Data.X509Certificates {
				certData, err := base64.StdEncoding.DecodeString(strings.TrimSpace(samlCert.Data))
				if err != nil {
					return nil, trace.Wrap(err)
				}
				cert, err := x509.ParseCertificate(certData)
				if err != nil {
					return nil, trace.Wrap(err, "failed to parse certificate in metadata")
				}
				certStore.Roots = append(certStore.Roots, cert)
			}
		}
	}

	if sc.GetCert() != "" {
		cert, err := tlsca.ParseCertificatePEM([]byte(sc.GetCert()))
		if err != nil {
			return nil, trace.Wrap(err)
		}
		certStore.Roots = append(certStore.Roots, cert)
	}
	if len(certStore.Roots) == 0 {
		return nil, trace.BadParameter("no identity provider certificate provided, either set certificate as a parameter or via entity_descriptor")
	}

	keyStore, err := utils.ParseSigningKeyStorePEM(sc.GetSigningKeyPair().PrivateKey, sc.GetSigningKeyPair().Cert)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:         sc.GetSSO(),
		IdentityProviderIssuer:         sc.GetIssuer(),
		ServiceProviderIssuer:          sc.GetServiceProviderIssuer(),
		AssertionConsumerServiceURL:    sc.GetAssertionConsumerService(),
		SignAuthnRequests:              true,
		SignAuthnRequestsCanonicalizer: dsig.MakeC14N11Canonicalizer(),
		AudienceURI:                    sc.GetAudience(),
		IDPCertificateStore:            &certStore,
		SPKeyStore:                     keyStore,
		Clock:                          dsig.NewFakeClock(clock),
		NameIdFormat:                   "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
	}

	// adfs specific settings
	if sc.GetAudience() == teleport.ADFS {
		if sp.SignAuthnRequests {
			// adfs does not support C14N11, we have to use the C14N10 canonicalizer
			sp.SignAuthnRequestsCanonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(dsig.DefaultPrefix)

			// at a minimum we require password protected transport
			sp.RequestedAuthnContext = &saml2.RequestedAuthnContext{
				Comparison: "minimum",
				Contexts:   []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
			}
		}
	}

	return sp, nil
}

// SAMLConnectorV2SchemaTemplate is a template JSON Schema for SAMLConnector
const SAMLConnectorV2SchemaTemplate = `{
	"type": "object",
	"additionalProperties": false,
	"required": ["kind", "spec", "metadata", "version"],
	"properties": {
	  "kind": {"type": "string"},
	  "version": {"type": "string", "default": "v1"},
	  "metadata": %v,
	  "spec": %v
	}
  }`

// SAMLConnectorSpecV2Schema is a JSON Schema for SAML Connector
var SAMLConnectorSpecV2Schema = fmt.Sprintf(`{
	"type": "object",
	"additionalProperties": false,
	"required": ["acs"],
	"properties": {
	  "issuer": {"type": "string"},
	  "sso": {"type": "string"},
	  "cert": {"type": "string"},
	  "provider": {"type": "string"},
	  "display": {"type": "string"},
	  "acs": {"type": "string"},
	  "audience": {"type": "string"},
	  "service_provider_issuer": {"type": "string"},
	  "entity_descriptor": {"type": "string"},
	  "entity_descriptor_url": {"type": "string"},
	  "attributes_to_roles": {
		"type": "array",
		"items": %v
	  },
	  "signing_key_pair": %v
	}
  }`, AttributeMappingSchema, SigningKeyPairSchema)

// AttributeMappingSchema is JSON schema for claim mapping
var AttributeMappingSchema = `{
	"type": "object",
	"additionalProperties": false,
	"required": ["name", "value" ],
	"properties": {
	  "name": {"type": "string"},
	  "value": {"type": "string"},
	  "roles": {
		"type": "array",
		"items": {
		  "type": "string"
		}
	  }
	}
  }`

// SigningKeyPairSchema is the JSON schema for signing key pair.
var SigningKeyPairSchema = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
	  "private_key": {"type": "string"},
	  "cert": {"type": "string"}
	}
  }`

// GetSAMLConnectorSchema returns schema for SAMLConnector
func GetSAMLConnectorSchema() string {
	return fmt.Sprintf(SAMLConnectorV2SchemaTemplate, MetadataSchema, SAMLConnectorSpecV2Schema)
}

// UnmarshalSAMLConnector unmarshals the SAMLConnector resource from JSON.
func UnmarshalSAMLConnector(bytes []byte, opts ...MarshalOption) (SAMLConnector, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var h ResourceHeader
	err = utils.FastUnmarshal(bytes, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch h.Version {
	case V2:
		var c SAMLConnectorV2
		if cfg.SkipValidation {
			if err := utils.FastUnmarshal(bytes, &c); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		} else {
			if err := utils.UnmarshalWithSchema(GetSAMLConnectorSchema(), &c, bytes); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		}

		if err := ValidateSAMLConnector(&c); err != nil {
			return nil, trace.Wrap(err)
		}

		if cfg.ID != 0 {
			c.SetResourceID(cfg.ID)
		}
		if !cfg.Expires.IsZero() {
			c.SetExpiry(cfg.Expires)
		}

		return &c, nil
	}

	return nil, trace.BadParameter("SAML connector resource version %v is not supported", h.Version)
}

// MarshalSAMLConnector marshals the SAMLConnector resource to JSON.
func MarshalSAMLConnector(c SAMLConnector, opts ...MarshalOption) ([]byte, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch connector := c.(type) {
	case *SAMLConnectorV2:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *connector
			copy.SetResourceID(0)
			connector = &copy
		}
		return utils.FastMarshal(connector)
	default:
		return nil, trace.BadParameter("unrecognized SAMLConnector version %T", c)
	}
}
