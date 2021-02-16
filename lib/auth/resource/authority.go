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

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

// CertRolesSchema defines cert roles schema
const CertRolesSchema = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"version": {"type": "string"},
			"roles": {
			"type": "array",
			"items": {
				"type": "string"
			}
		}
	}
}`

// MarshalCertRoles marshal roles list to OpenSSH
func MarshalCertRoles(roles []string) (string, error) {
	out, err := json.Marshal(types.CertRoles{Version: types.V1, Roles: roles})
	if err != nil {
		return "", trace.Wrap(err)
	}
	return string(out), err
}

// UnmarshalCertRoles marshals roles list to OpenSSH format
func UnmarshalCertRoles(data string) ([]string, error) {
	var certRoles types.CertRoles
	if err := utils.UnmarshalWithSchema(CertRolesSchema, &certRoles, []byte(data)); err != nil {
		return nil, trace.BadParameter(err.Error())
	}
	return certRoles.Roles, nil
}

// CertAuthoritySpecV2Schema is JSON schema for cert authority V2
const CertAuthoritySpecV2Schema = `{
	"type": "object",
	"additionalProperties": false,
	"required": ["type", "cluster_name"],
	"properties": {
		"type": {"type": "string"},
		"cluster_name": {"type": "string"},
		"checking_keys": {
			"type": "array",
			"items": {
				"type": "string"
			}
		},
		"signing_keys": {
			"type": "array",
			"items": {
				"type": "string"
			}
		},
		"roles": {
			"type": "array",
			"items": {
				"type": "string"
			}
		},
		"tls_key_pairs":  {
			"type": "array",
			"items": {
				"type": "object",
				"additionalProperties": false,
				"properties": {
					"cert": {"type": "string"},
					"key": {"type": "string"}
				}
			}
		},
		"jwt_key_pairs":  {
			"type": "array",
			"items": {
				"type": "object",
				"additionalProperties": false,
				"properties": {
					"public_key": {"type": "string"},
					"private_key": {"type": "string"}
				}
			}
		},
		"signing_alg": {"type": "integer"},
		"rotation": %v,
		"role_map": %v
	}
}`

// RotationSchema is a JSON validation schema of the CA rotation state object.
const RotationSchema = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"state": {"type": "string"},
		"phase": {"type": "string"},
		"mode": {"type": "string"},
		"current_id": {"type": "string"},
		"started": {"type": "string"},
		"grace_period": {"type": "string"},
		"last_rotated": {"type": "string"},
		"schedule": {
			"type": "object",
			"properties": {
				"update_clients": {"type": "string"},
				"update_servers": {"type": "string"},
				"standby": {"type": "string"}
			}
		}
	}
}`

// GetCertAuthoritySchema returns JSON Schema for cert authorities
func GetCertAuthoritySchema() string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, fmt.Sprintf(CertAuthoritySpecV2Schema, RotationSchema, RoleMapSchema), DefaultDefinitions)
}

// UnmarshalCertAuthority unmarshals the CertAuthority resource to JSON.
func UnmarshalCertAuthority(bytes []byte, opts ...auth.MarshalOption) (types.CertAuthority, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var h types.ResourceHeader
	err = utils.FastUnmarshal(bytes, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch h.Version {
	case types.V2:
		var ca types.CertAuthorityV2
		if cfg.SkipValidation {
			if err := utils.FastUnmarshal(bytes, &ca); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		} else {
			if err := utils.UnmarshalWithSchema(GetCertAuthoritySchema(), &ca, bytes); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		}
		if err := auth.ValidateCertAuthority(&ca); err != nil {
			return nil, trace.Wrap(err)
		}
		if cfg.ID != 0 {
			ca.SetResourceID(cfg.ID)
		}
		return &ca, nil
	}

	return nil, trace.BadParameter("cert authority resource version %v is not supported", h.Version)
}

// MarshalCertAuthority marshals the CertAuthority resource to JSON.
func MarshalCertAuthority(ca types.CertAuthority, opts ...auth.MarshalOption) ([]byte, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch authority := ca.(type) {
	case *types.CertAuthorityV2:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *authority
			copy.SetResourceID(0)
			authority = &copy
		}
		return utils.FastMarshal(authority)
	default:
		return nil, trace.BadParameter("unrecognized certificate authority version %T", ca)
	}
}
