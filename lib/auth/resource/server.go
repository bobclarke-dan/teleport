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
	"fmt"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

// ServerSpecV2Schema is JSON schema for server
const ServerSpecV2Schema = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
	  "version": {"type": "string"},
	  "addr": {"type": "string"},
	  "protocol": {"type": "integer"},
	  "public_addr": {"type": "string"},
	  "apps":  {
		"type": ["array"],
		"items": {
		  "type": "object",
		  "additionalProperties": false,
		  "properties": {
			  "name": {"type": "string"},
			  "uri": {"type": "string"},
			  "public_addr": {"type": "string"},
			  "insecure_skip_verify": {"type": "boolean"},
			  "rewrite": {
			  "type": "object",
			  "additionalProperties": false,
			  "properties": {
				"redirect": {"type": ["array"], "items": {"type": "string"}}
			  }
			},
			"labels": {
			  "type": "object",
			  "additionalProperties": false,
			  "patternProperties": {
				"^.*$":  { "type": "string" }
			  }
			},
			"commands": {
			  "type": "object",
			  "additionalProperties": false,
			  "patternProperties": {
				"^.*$": {
				  "type": "object",
				  "additionalProperties": false,
				  "required": ["command"],
				  "properties": {
					  "command": {"type": "array", "items": {"type": "string"}},
					"period": {"type": "string"},
					"result": {"type": "string"}
				  }
				}
			  }
			}
		  }
		}
	  },
	  "hostname": {"type": "string"},
	  "use_tunnel": {"type": "boolean"},
	  "labels": {
		  "type": "object",
		  "additionalProperties": false,
		"patternProperties": {
		  "^.*$":  { "type": "string" }
		}
	  },
	  "cmd_labels": {
		"type": "object",
		"additionalProperties": false,
		"patternProperties": {
		  "^.*$": {
			"type": "object",
			"additionalProperties": false,
			"required": ["command"],
			"properties": {
			  "command": {"type": "array", "items": {"type": "string"}},
			  "period": {"type": "string"},
			  "result": {"type": "string"}
			}
		  }
		}
	  },
	  "kube_clusters": {
		"type": "array",
		"items": {
		  "type": "object",
		  "required": ["name"],
		  "properties": {
		  "name": {"type": "string"},
		  "static_labels": {
			"type": "object",
			"additionalProperties": false,
			"patternProperties": {
			  "^.*$":  { "type": "string" }
			}
		  },
		  "dynamic_labels": {
			"type": "object",
			"additionalProperties": false,
			"patternProperties": {
			  "^.*$": {
				"type": "object",
				"additionalProperties": false,
				"required": ["command"],
				"properties": {
				  "command": {"type": "array", "items": {"type": "string"}},
				  "period": {"type": "string"},
				  "result": {"type": "string"}
				}
			  }
			}
		  }
		}
	  }
	},
	"rotation": %v
  }
  }`

// GetServerSchema returns role schema with optionally injected
// schema for extensions
func GetServerSchema() string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, fmt.Sprintf(ServerSpecV2Schema, RotationSchema), DefaultDefinitions)
}

// UnmarshalServerResource unmarshals role from JSON or YAML,
// sets defaults and checks the schema
func UnmarshalServerResource(data []byte, kind string, cfg *auth.MarshalConfig) (types.Server, error) {
	if len(data) == 0 {
		return nil, trace.BadParameter("missing server data")
	}

	var h types.ResourceHeader
	err := utils.FastUnmarshal(data, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch h.Version {
	case types.V2:
		var s types.ServerV2

		if cfg.SkipValidation {
			if err := utils.FastUnmarshal(data, &s); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		} else {
			if err := utils.UnmarshalWithSchema(GetServerSchema(), &s, data); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		}
		s.Kind = kind
		if err := s.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		if cfg.ID != 0 {
			s.SetResourceID(cfg.ID)
		}
		if !cfg.Expires.IsZero() {
			s.SetExpiry(cfg.Expires)
		}
		return &s, nil
	}
	return nil, trace.BadParameter("server resource version %q is not supported", h.Version)
}

// UnmarshalServer unmarshals the Server resource from JSON.
func UnmarshalServer(bytes []byte, kind string, opts ...auth.MarshalOption) (types.Server, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing server data")
	}

	var h types.ResourceHeader
	if err = utils.FastUnmarshal(bytes, &h); err != nil {
		return nil, trace.Wrap(err)
	}

	switch h.Version {
	case types.V2:
		var s types.ServerV2

		if cfg.SkipValidation {
			if err := utils.FastUnmarshal(bytes, &s); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		} else {
			if err := utils.UnmarshalWithSchema(GetServerSchema(), &s, bytes); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		}
		s.Kind = kind
		if err := s.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		if cfg.ID != 0 {
			s.SetResourceID(cfg.ID)
		}
		if !cfg.Expires.IsZero() {
			s.SetExpiry(cfg.Expires)
		}
		return &s, nil
	}
	return nil, trace.BadParameter("server resource version %q is not supported", h.Version)
}

// MarshalServer marshals the Server resource to JSON.
func MarshalServer(s types.Server, opts ...auth.MarshalOption) ([]byte, error) {
	if err := s.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch server := s.(type) {
	case *types.ServerV2:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *server
			copy.SetResourceID(0)
			server = &copy
		}
		return utils.FastMarshal(server)
	default:
		return nil, trace.BadParameter("unrecognized server version %T", s)
	}
}

// UnmarshalServers unmarshals a list of Server resources.
func UnmarshalServers(bytes []byte) ([]types.Server, error) {
	var servers []types.ServerV2

	err := utils.FastUnmarshal(bytes, &servers)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	out := make([]types.Server, len(servers))
	for i, v := range servers {
		out[i] = types.Server(&v)
	}
	return out, nil
}

// MarshalServers marshals a list of Server resources.
func MarshalServers(s []types.Server) ([]byte, error) {
	bytes, err := utils.FastMarshal(s)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return bytes, nil
}
