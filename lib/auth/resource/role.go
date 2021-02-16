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

package resource

import (
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

// ExtractFromCertificate will extract roles and traits from a *ssh.Certificate
// or from the backend if they do not exist in the certificate.
func ExtractFromCertificate(access auth.UserGetter, cert *ssh.Certificate) ([]string, wrappers.Traits, error) {
	// For legacy certificates, fetch roles and traits from the services.User
	// object in the backend.
	if isFormatOld(cert) {
		u, err := access.GetUser(cert.KeyId, false)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
		log.Warnf("User %v using old style SSH certificate, fetching roles and traits "+
			"from backend. If the identity provider allows username changes, this can "+
			"potentially allow an attacker to change the role of the existing user. "+
			"It's recommended to upgrade to standard SSH certificates.", cert.KeyId)
		return u.GetRoles(), u.GetTraits(), nil
	}

	// Standard certificates have the roles and traits embedded in them.
	roles, err := extractRolesFromCert(cert)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	traits, err := extractTraitsFromCert(cert)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	return roles, traits, nil
}

// extractRolesFromCert extracts roles from certificate metadata extensions.
func extractRolesFromCert(cert *ssh.Certificate) ([]string, error) {
	data, ok := cert.Extensions[teleport.CertExtensionTeleportRoles]
	if !ok {
		return nil, trace.NotFound("no roles found")
	}
	return UnmarshalCertRoles(data)
}

// extractTraitsFromCert extracts traits from the certificate extensions.
func extractTraitsFromCert(cert *ssh.Certificate) (wrappers.Traits, error) {
	rawTraits, ok := cert.Extensions[teleport.CertExtensionTeleportTraits]
	if !ok {
		return nil, trace.NotFound("no traits found")
	}
	var traits wrappers.Traits
	err := wrappers.UnmarshalTraits([]byte(rawTraits), &traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return traits, nil
}

// isFormatOld returns true if roles and traits were not found in the
// *ssh.Certificate.
func isFormatOld(cert *ssh.Certificate) bool {
	_, hasRoles := cert.Extensions[teleport.CertExtensionTeleportRoles]
	_, hasTraits := cert.Extensions[teleport.CertExtensionTeleportTraits]

	if hasRoles || hasTraits {
		return false
	}
	return true
}

// RoleSpecV3SchemaTemplate is JSON schema for RoleSpecV3
const RoleSpecV3SchemaTemplate = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
	  "max_session_ttl": { "type": "string" },
	  "options": {
		"type": "object",
		"additionalProperties": false,
		"properties": {
		  "forward_agent": { "type": ["boolean", "string"] },
		  "permit_x11_forwarding": { "type": ["boolean", "string"] },
		  "max_session_ttl": { "type": "string" },
		  "port_forwarding": { "type": ["boolean", "string"] },
		  "cert_format": { "type": "string" },
		  "client_idle_timeout": { "type": "string" },
		  "disconnect_expired_cert": { "type": ["boolean", "string"] },
		  "enhanced_recording": {
			"type": "array",
			"items": { "type": "string" }
		  },
		  "max_connections": { "type": "number" },
		  "max_sessions": {"type": "number"},
		  "request_access": { "type": "string" },
		  "request_prompt": { "type": "string" }
		}
	  },
	  "allow": { "$ref": "#/definitions/role_condition" },
	  "deny": { "$ref": "#/definitions/role_condition" }%v
	}
  }`

// RoleSpecV3SchemaDefinitions is JSON schema for RoleSpecV3 definitions
const RoleSpecV3SchemaDefinitions = `
	  "definitions": {
		"role_condition": {
		  "namespaces": {
			"type": "array",
			"items": { "type": "string" }
		  },
		  "node_labels": {
			"type": "object",
			"additionalProperties": false,
			"patternProperties": {
			  "^[a-zA-Z/.0-9_*-]+$": { "anyOf": [{"type": "string"}, { "type": "array", "items": {"type": "string"}}]}
			}
		  },
		  "cluster_labels": {
			"type": "object",
			"additionalProperties": false,
			"patternProperties": {
			  "^[a-zA-Z/.0-9_*-]+$": { "anyOf": [{"type": "string"}, { "type": "array", "items": {"type": "string"}}]}
			}
		  },
		  "logins": {
			"type": "array",
			"items": { "type": "string" }
		  },
		  "kubernetes_groups": {
			"type": "array",
			"items": { "type": "string" }
		  },
		  "db_labels": {
			"type": "object",
			"additionalProperties": false,
			"patternProperties": {
			  "^[a-zA-Z/.0-9_*-]+$": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]}
			}
		  },
		  "db_names": {
			"type": "array",
			"items": {"type": "string"}
		  },
		  "db_users": {
			"type": "array",
			"items": {"type": "string"}
		  },
		  "request": {
			"type": "object",
			"additionalProperties": false,
			"properties": {
			  "roles": {
				"type": "array",
				"items": { "type": "string" }
			  },
			  "claims_to_roles": {
				"type": "object",
				"additionalProperties": false,
				"properties": {
				  "claim": {"type": "string"},
				  "value": {"type": "string"},
				  "roles": {
					"type": "array",
					"items": {
					  "type": "string"
					}
				  }
				}
			  }
			}
		  },
		  "rules": {
			"type": "array",
			"items": {
			  "type": "object",
			  "additionalProperties": false,
			  "properties": {
				"resources": {
				  "type": "array",
				  "items": { "type": "string" }
				},
				"verbs": {
				  "type": "array",
				  "items": { "type": "string" }
				},
				"where": {
				   "type": "string"
				},
				"actions": {
				  "type": "array",
				  "items": { "type": "string" }
				}
			  }
			}
		  }
		}
	  }
	`

// GetRoleSchema returns role schema for the version requested with optionally
// injected schema for extensions.
func GetRoleSchema(version string, extensionSchema string) string {
	schemaDefinitions := "," + RoleSpecV3SchemaDefinitions
	schemaTemplate := RoleSpecV3SchemaTemplate

	schema := fmt.Sprintf(schemaTemplate, ``)
	if extensionSchema != "" {
		schema = fmt.Sprintf(schemaTemplate, ","+extensionSchema)
	}

	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, schema, schemaDefinitions)
}

// UnmarshalRole unmarshals the Role resource from JSON.
func UnmarshalRole(bytes []byte, opts ...auth.MarshalOption) (types.Role, error) {
	var h types.ResourceHeader
	err := json.Unmarshal(bytes, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch h.Version {
	case types.V3:
		var role types.RoleV3
		if cfg.SkipValidation {
			if err := utils.FastUnmarshal(bytes, &role); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		} else {
			if err := utils.UnmarshalWithSchema(GetRoleSchema(types.V3, ""), &role, bytes); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		}

		if err := auth.ValidateRole(&role); err != nil {
			return nil, trace.Wrap(err)
		}

		if cfg.ID != 0 {
			role.SetResourceID(cfg.ID)
		}
		if !cfg.Expires.IsZero() {
			role.SetExpiry(cfg.Expires)
		}
		return &role, nil
	}

	return nil, trace.BadParameter("role version %q is not supported", h.Version)
}

// MarshalRole marshals the Role resource to JSON.
func MarshalRole(r types.Role, opts ...auth.MarshalOption) ([]byte, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch role := r.(type) {
	case *types.RoleV3:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *role
			copy.SetResourceID(0)
			role = &copy
		}
		return utils.FastMarshal(role)
	default:
		return nil, trace.BadParameter("unrecognized role version %T", r)
	}
}
