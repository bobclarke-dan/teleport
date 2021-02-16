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

package resource

import (
	"fmt"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

// AccessRequestSpecSchema is JSON schema for AccessRequestSpec
const AccessRequestSpecSchema = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"user": { "type": "string" },
		"roles": {
			"type": "array",
			"items": { "type": "string" }
		},
		"state": { "type": "integer" },
		"created": { "type": "string" },
		"expires": { "type": "string" },
		"request_reason": { "type": "string" },
		"resolve_reason": { "type": "string" },
		"resolve_annotations": { "type": "object" },
		"system_annotations": { "type": "object" }
	}
}`

// GetAccessRequestSchema gets the full AccessRequest JSON schema
func GetAccessRequestSchema() string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, AccessRequestSpecSchema, DefaultDefinitions)
}

// UnmarshalAccessRequest unmarshals the AccessRequest resource from JSON.
func UnmarshalAccessRequest(data []byte, opts ...auth.MarshalOption) (types.AccessRequest, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var req types.AccessRequestV3
	if cfg.SkipValidation {
		if err := utils.FastUnmarshal(data, &req); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if err := utils.UnmarshalWithSchema(GetAccessRequestSchema(), &req, data); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	if err := auth.ValidateAccessRequest(&req); err != nil {
		return nil, trace.Wrap(err)
	}
	if cfg.ID != 0 {
		req.SetResourceID(cfg.ID)
	}
	if !cfg.Expires.IsZero() {
		req.SetExpiry(cfg.Expires)
	}
	return &req, nil
}

// MarshalAccessRequest marshals the AccessRequest resource to JSON.
func MarshalAccessRequest(req types.AccessRequest, opts ...auth.MarshalOption) ([]byte, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch r := req.(type) {
	case *types.AccessRequestV3:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			cp := *r
			cp.SetResourceID(0)
			r = &cp
		}
		return utils.FastMarshal(r)
	default:
		return nil, trace.BadParameter("unrecognized access request type: %T", req)
	}
}
