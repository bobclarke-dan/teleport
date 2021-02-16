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

// ProvisionTokenSpecV2Schema is a JSON schema for provision token
const ProvisionTokenSpecV2Schema = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
	  "roles": {"type": "array", "items": {"type": "string"}}
	}
  }`

// GetProvisionTokenSchema returns provision token schema
func GetProvisionTokenSchema() string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, ProvisionTokenSpecV2Schema, DefaultDefinitions)
}

// UnmarshalProvisionToken unmarshals the ProvisionToken resource from JSON.
func UnmarshalProvisionToken(data []byte, opts ...auth.MarshalOption) (types.ProvisionToken, error) {
	if len(data) == 0 {
		return nil, trace.BadParameter("missing provision token data")
	}

	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var h types.ResourceHeader
	err = utils.FastUnmarshal(data, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch h.Version {
	case "":
		var p types.ProvisionTokenV1
		err := utils.FastUnmarshal(data, &p)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		v2 := p.V2()
		if cfg.ID != 0 {
			v2.SetResourceID(cfg.ID)
		}
		return v2, nil
	case types.V2:
		var p types.ProvisionTokenV2
		if cfg.SkipValidation {
			if err := utils.FastUnmarshal(data, &p); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		} else {
			if err := utils.UnmarshalWithSchema(GetProvisionTokenSchema(), &p, data); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		}
		if err := p.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		if cfg.ID != 0 {
			p.SetResourceID(cfg.ID)
		}
		return &p, nil
	}
	return nil, trace.BadParameter("server resource version %v is not supported", h.Version)
}

// MarshalProvisionToken marshals the ProvisionToken resource to JSON.
func MarshalProvisionToken(t types.ProvisionToken, opts ...auth.MarshalOption) ([]byte, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	type token1 interface {
		V1() *types.ProvisionTokenV1
	}
	type token2 interface {
		V2() *types.ProvisionTokenV2
	}

	version := cfg.GetVersion()
	switch version {
	case types.V1:
		v, ok := t.(token1)
		if !ok {
			return nil, trace.BadParameter("don't know how to marshal %v", types.V1)
		}
		return utils.FastMarshal(v.V1())
	case types.V2:
		v, ok := t.(token2)
		if !ok {
			return nil, trace.BadParameter("don't know how to marshal %v", types.V2)
		}
		return utils.FastMarshal(v.V2())
	default:
		return nil, trace.BadParameter("version %v is not supported", version)
	}
}
