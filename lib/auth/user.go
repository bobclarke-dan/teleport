/*
Copyright 2015 Gravitational, Inc.

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

// Package auth implements certificate signing authority and access control server
// Authority server is composed of several parts:
//
// * Authority server itself that implements signing and acl logic
// * HTTP server wrapper for authority server
// * HTTP client wrapper
//
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

// CreateUser inserts a new user entry in a backend.
func (s *Server) CreateUser(ctx context.Context, user types.User) error {
	if user.GetCreatedBy().IsEmpty() {
		user.SetCreatedBy(types.CreatedBy{
			User: types.UserRef{Name: clientUsername(ctx)},
			Time: s.GetClock().Now().UTC(),
		})
	}

	// TODO: ctx is being swallowed here because the current implementation of
	// s.Identity.CreateUser is an older implementation that does not curently
	// accept a context.
	if err := s.Services.ServerIdentity.CreateUser(user); err != nil {
		return trace.Wrap(err)
	}

	var connectorName string
	if user.GetCreatedBy().Connector == nil {
		connectorName = teleport.Local
	} else {
		connectorName = user.GetCreatedBy().Connector.ID
	}

	if err := s.emitter.EmitAuditEvent(ctx, &events.UserCreate{
		Metadata: events.Metadata{
			Type: events.UserCreateEvent,
			Code: events.UserCreateCode,
		},
		UserMetadata: events.UserMetadata{
			User: user.GetCreatedBy().User.Name,
		},
		ResourceMetadata: events.ResourceMetadata{
			Name:    user.GetName(),
			Expires: user.Expiry(),
		},
		Connector: connectorName,
		Roles:     user.GetRoles(),
	}); err != nil {
		log.WithError(err).Warn("Failed to emit user create event.")
	}

	return nil
}

// UpdateUser updates an existing user in a backend.
func (s *Server) UpdateUser(ctx context.Context, user types.User) error {
	if err := s.Services.ServerIdentity.UpdateUser(ctx, user); err != nil {
		return trace.Wrap(err)
	}

	var connectorName string
	if user.GetCreatedBy().Connector == nil {
		connectorName = teleport.Local
	} else {
		connectorName = user.GetCreatedBy().Connector.ID
	}

	if err := s.emitter.EmitAuditEvent(ctx, &events.UserCreate{
		Metadata: events.Metadata{
			Type: events.UserUpdatedEvent,
			Code: events.UserUpdateCode,
		},
		UserMetadata: events.UserMetadata{
			User: clientUsername(ctx),
		},
		ResourceMetadata: events.ResourceMetadata{
			Name:    user.GetName(),
			Expires: user.Expiry(),
		},
		Connector: connectorName,
		Roles:     user.GetRoles(),
	}); err != nil {
		log.WithError(err).Warn("Failed to emit user update event.")
	}

	return nil
}

// UpsertUser updates a user.
func (s *Server) UpsertUser(user types.User) error {
	err := s.Services.ServerIdentity.UpsertUser(user)
	if err != nil {
		return trace.Wrap(err)
	}

	var connectorName string
	if user.GetCreatedBy().Connector == nil {
		connectorName = teleport.Local
	} else {
		connectorName = user.GetCreatedBy().Connector.ID
	}

	if err := s.emitter.EmitAuditEvent(s.closeCtx, &events.UserCreate{
		Metadata: events.Metadata{
			Type: events.UserCreateEvent,
			Code: events.UserCreateCode,
		},
		UserMetadata: events.UserMetadata{
			User: user.GetName(),
		},
		ResourceMetadata: events.ResourceMetadata{
			Name:    user.GetName(),
			Expires: user.Expiry(),
		},
		Connector: connectorName,
		Roles:     user.GetRoles(),
	}); err != nil {
		log.WithError(err).Warn("Failed to emit user upsert event.")
	}

	return nil
}

// DeleteUser deletes an existng user in a backend by username.
func (s *Server) DeleteUser(ctx context.Context, user string) error {
	role, err := s.Services.ServerAccess.GetRole(RoleNameForUser(user))
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	} else {
		if err := s.Services.ServerAccess.DeleteRole(ctx, role.GetName()); err != nil {
			if !trace.IsNotFound(err) {
				return trace.Wrap(err)
			}
		}
	}

	err = s.Services.ServerIdentity.DeleteUser(ctx, user)
	if err != nil {
		return trace.Wrap(err)
	}

	// If the user was successfully deleted, emit an event.
	if err := s.emitter.EmitAuditEvent(s.closeCtx, &events.UserDelete{
		Metadata: events.Metadata{
			Type: events.UserDeleteEvent,
			Code: events.UserDeleteCode,
		},
		UserMetadata: events.UserMetadata{
			User: clientUsername(ctx),
		},
		ResourceMetadata: events.ResourceMetadata{
			Name: user,
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit user delete event.")
	}

	return nil
}

// ValidateUser validates the User and sets default values
func ValidateUser(u User) error {
	if err := u.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if localAuth := u.GetLocalAuth(); localAuth != nil {
		if err := ValidateLocalAuthSecrets(localAuth); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// UsersEquals checks if the users are equal
func UsersEquals(u User, other User) bool {
	if u.GetName() != other.GetName() {
		return false
	}
	otherIdentities := other.GetOIDCIdentities()
	if len(u.GetOIDCIdentities()) != len(otherIdentities) {
		return false
	}
	for i := range u.GetOIDCIdentities() {
		if !u.GetOIDCIdentities()[i].Equals(&otherIdentities[i]) {
			return false
		}
	}
	otherSAMLIdentities := other.GetSAMLIdentities()
	if len(u.GetSAMLIdentities()) != len(otherSAMLIdentities) {
		return false
	}
	for i := range u.GetSAMLIdentities() {
		if !u.GetSAMLIdentities()[i].Equals(&otherSAMLIdentities[i]) {
			return false
		}
	}
	otherGithubIdentities := other.GetGithubIdentities()
	if len(u.GetGithubIdentities()) != len(otherGithubIdentities) {
		return false
	}
	for i := range u.GetGithubIdentities() {
		if !u.GetGithubIdentities()[i].Equals(&otherGithubIdentities[i]) {
			return false
		}
	}
	return LocalAuthSecretsEquals(u.GetLocalAuth(), other.GetLocalAuth())
}

// LoginAttempt represents successful or unsuccessful attempt for user to login
type LoginAttempt struct {
	// Time is time of the attempt
	Time time.Time `json:"time"`
	// Success indicates whether attempt was successful
	Success bool `json:"bool"`
}

// Check checks parameters
func (la *LoginAttempt) Check() error {
	if la.Time.IsZero() {
		return trace.BadParameter("missing parameter time")
	}
	return nil
}

// UserSpecV2SchemaTemplate is JSON schema for V2 user
const UserSpecV2SchemaTemplate = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"expires": {"type": "string"},
		"roles": {
			"type": "array",
			"items": {
				"type": "string"
			}
		},
		"traits": {
			"type": "object",
			"additionalProperties": false,
			"patternProperties": {
				"^.+$": {
					"type": ["array", "null"],
					"items": {
						"type": "string"
					}
				}
			}
		},
		"oidc_identities": {
			"type": "array",
			"items": %v
		},
		"saml_identities": {
			"type": "array",
			"items": %v
		},
		"github_identities": {
			"type": "array",
			"items": %v
		},
		"status": %v,
		"created_by": %v,
		"local_auth": %v%v
	}
}`

// CreatedBySchema is JSON schema for CreatedBy
const CreatedBySchema = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"connector": {
			"additionalProperties": false,
			"type": "object",
			"properties": {
			"type": {"type": "string"},
			"id": {"type": "string"},
			"identity": {"type": "string"}
			}
		},
		"time": {"type": "string"},
		"user": {
			"type": "object",
			"additionalProperties": false,
			"properties": {"name": {"type": "string"}}
		}
	}
}`

// ExternalIdentitySchema is JSON schema for ExternalIdentity
const ExternalIdentitySchema = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"connector_id": {"type": "string"},
		"username": {"type": "string"}
	}
}`

// LoginStatusSchema is JSON schema for LoginStatus
const LoginStatusSchema = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"is_locked": {"type": "boolean"},
		"locked_message": {"type": "string"},
		"locked_time": {"type": "string"},
		"lock_expires": {"type": "string"}
	}
}`

// GetUserSchema returns role schema with optionally injected
// schema for extensions
func GetUserSchema(extensionSchema string) string {
	var userSchema string
	if extensionSchema == "" {
		userSchema = fmt.Sprintf(UserSpecV2SchemaTemplate, ExternalIdentitySchema, ExternalIdentitySchema, ExternalIdentitySchema, LoginStatusSchema, CreatedBySchema, LocalAuthSecretsSchema, ``)
	} else {
		userSchema = fmt.Sprintf(UserSpecV2SchemaTemplate, ExternalIdentitySchema, ExternalIdentitySchema, ExternalIdentitySchema, LoginStatusSchema, CreatedBySchema, LocalAuthSecretsSchema, ", "+extensionSchema)
	}
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, userSchema, DefaultDefinitions)
}

// UnmarshalUser unmarshals the User resource from JSON.
func UnmarshalUser(bytes []byte, opts ...MarshalOption) (User, error) {
	var h ResourceHeader
	err := json.Unmarshal(bytes, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch h.Version {
	case V2:
		var u UserV2
		if cfg.SkipValidation {
			if err := utils.FastUnmarshal(bytes, &u); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		} else {
			if err := utils.UnmarshalWithSchema(GetUserSchema(""), &u, bytes); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		}

		if err := ValidateUser(&u); err != nil {
			return nil, trace.Wrap(err)
		}
		if cfg.ID != 0 {
			u.SetResourceID(cfg.ID)
		}
		if !cfg.Expires.IsZero() {
			u.SetExpiry(cfg.Expires)
		}

		return &u, nil
	}
	return nil, trace.BadParameter("user resource version %v is not supported", h.Version)
}

// MarshalUser marshals the User resource to JSON.
func MarshalUser(u User, opts ...MarshalOption) ([]byte, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch user := u.(type) {
	case *UserV2:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *user
			copy.SetResourceID(0)
			user = &copy
		}
		return utils.FastMarshal(user)
	default:
		return nil, trace.BadParameter("unrecognized user version %T", u)
	}
}
