/*
Copyright 2015-2018 Gravitational, Inc.

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

package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"

	"github.com/gravitational/trace"
	"github.com/vulcand/predicate/builder"
)

// NewAdminContext returns new admin auth context
func NewAdminContext() (*Context, error) {
	authContext, err := contextForBuiltinRole("", nil, teleport.RoleAdmin, fmt.Sprintf("%v", teleport.RoleAdmin))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return authContext, nil
}

// NewAuthorizer returns new authorizer using backends
func NewAuthorizer(access auth.Access, identity auth.UserGetter, trust auth.Trust) (Authorizer, error) {
	if access == nil {
		return nil, trace.BadParameter("missing parameter access")
	}
	if identity == nil {
		return nil, trace.BadParameter("missing parameter identity")
	}
	if trust == nil {
		return nil, trace.BadParameter("missing parameter trust")
	}
	return &authorizer{access: access, identity: identity, trust: trust}, nil
}

// Authorizer authorizes identity and returns auth context
type Authorizer interface {
	// Authorize authorizes user based on identity supplied via context
	Authorize(ctx context.Context) (*Context, error)
}

// authorizer creates new local authorizer
type authorizer struct {
	access   auth.Access
	identity auth.UserGetter
	trust    auth.Trust
}

// AuthContext is authorization context
type Context struct {
	// User is the user name
	User types.User
	// Checker is access checker
	Checker auth.AccessChecker
	// Identity holds user identity - whether it's a local or remote user,
	// local or remote node, proxy or auth server
	Identity IdentityGetter
}

// Authorize authorizes user based on identity supplied via context
func (a *authorizer) Authorize(ctx context.Context) (*Context, error) {
	if ctx == nil {
		return nil, trace.AccessDenied("missing authentication context")
	}
	userI := ctx.Value(ContextUser)
	userWithIdentity, ok := userI.(IdentityGetter)
	if !ok {
		return nil, trace.AccessDenied("unsupported context type %T", userI)
	}
	authContext, err := a.fromUser(userI)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	authContext.Identity = userWithIdentity
	return authContext, nil
}

func (a *authorizer) fromUser(userI interface{}) (*Context, error) {
	switch user := userI.(type) {
	case LocalUser:
		return a.authorizeLocalUser(user)
	case RemoteUser:
		return a.authorizeRemoteUser(user)
	case BuiltinRole:
		return a.authorizeBuiltinRole(user)
	case RemoteBuiltinRole:
		return a.authorizeRemoteBuiltinRole(user)
	default:
		return nil, trace.AccessDenied("unsupported context type %T", userI)
	}
}

// authorizeLocalUser returns authz context based on the username
func (a *authorizer) authorizeLocalUser(u LocalUser) (*Context, error) {
	return contextForLocalUser(u, a.identity, a.access)
}

// authorizeRemoteUser returns checker based on cert authority roles
func (a *authorizer) authorizeRemoteUser(u RemoteUser) (*Context, error) {
	ca, err := a.trust.GetCertAuthority(types.CertAuthID{Type: types.UserCA, DomainName: u.ClusterName}, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleNames, err := auth.MapRoles(ca.CombinedMapping(), u.RemoteRoles)
	if err != nil {
		return nil, trace.AccessDenied("failed to map roles for remote user %q from cluster %q", u.Username, u.ClusterName)
	}
	if len(roleNames) == 0 {
		return nil, trace.AccessDenied("no roles mapped for remote user %q from cluster %q", u.Username, u.ClusterName)
	}
	// Set "logins" trait and "kubernetes_groups" for the remote user. This allows Teleport to work by
	// passing exact logins, kubernetes groups and users to the remote cluster. Note that claims (OIDC/SAML)
	// are not passed, but rather the exact logins, this is done to prevent
	// leaking too much of identity to the remote cluster, and instead of focus
	// on main cluster's interpretation of this identity
	traits := map[string][]string{
		teleport.TraitLogins:     u.Principals,
		teleport.TraitKubeGroups: u.KubernetesGroups,
		teleport.TraitKubeUsers:  u.KubernetesUsers,
		teleport.TraitDBNames:    u.DatabaseNames,
		teleport.TraitDBUsers:    u.DatabaseUsers,
	}
	log.Debugf("Mapped roles %v of remote user %q to local roles %v and traits %v.",
		u.RemoteRoles, u.Username, roleNames, traits)
	checker, err := auth.FetchRoles(roleNames, a.access, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// The user is prefixed with "remote-" and suffixed with cluster name with
	// the hope that it does not match a real local user.
	user, err := types.NewUser(fmt.Sprintf("remote-%v-%v", u.Username, u.ClusterName))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user.SetTraits(traits)

	// Set the list of roles this user has in the remote cluster.
	user.SetRoles(roleNames)

	return &Context{
		User:    user,
		Checker: RemoteUserRoleSet{checker},
	}, nil
}

// authorizeBuiltinRole authorizes builtin role
func (a *authorizer) authorizeBuiltinRole(r BuiltinRole) (*Context, error) {
	config, err := r.GetClusterConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return contextForBuiltinRole(r.ClusterName, config, r.Role, r.Username)
}

func (a *authorizer) authorizeRemoteBuiltinRole(r RemoteBuiltinRole) (*Context, error) {
	if r.Role != teleport.RoleProxy {
		return nil, trace.AccessDenied("access denied for remote %v connecting to cluster", r.Role)
	}
	roles, err := auth.FromSpec(
		string(teleport.RoleRemoteProxy),
		types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces: []string{types.Wildcard},
				Rules: []types.Rule{
					types.NewRule(types.KindNode, auth.RO()),
					types.NewRule(types.KindProxy, auth.RO()),
					types.NewRule(types.KindCertAuthority, auth.ReadNoSecrets()),
					types.NewRule(types.KindNamespace, auth.RO()),
					types.NewRule(types.KindUser, auth.RO()),
					types.NewRule(types.KindRole, auth.RO()),
					types.NewRule(types.KindAuthServer, auth.RO()),
					types.NewRule(types.KindReverseTunnel, auth.RO()),
					types.NewRule(types.KindTunnelConnection, auth.RO()),
					types.NewRule(types.KindClusterConfig, auth.RO()),
					types.NewRule(types.KindKubeService, auth.RO()),
					// this rule allows remote proxy to update the cluster's certificate authorities
					// during certificates renewal
					{
						Resources: []string{types.KindCertAuthority},
						// It is important that remote proxy can only rotate
						// existing certificate authority, and not create or update new ones
						Verbs: []string{types.VerbRead, types.VerbRotate},
						// allow administrative access to the certificate authority names
						// matching the cluster name only
						Where: builder.Equals(auth.ResourceNameExpr, builder.String(r.ClusterName)).String(),
					},
				},
			},
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user, err := types.NewUser(r.Username)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user.SetRoles([]string{string(teleport.RoleRemoteProxy)})
	return &Context{
		User:    user,
		Checker: RemoteBuiltinRoleSet{roles},
	}, nil
}

// GetCheckerForBuiltinRole returns checkers for embedded builtin role
func GetCheckerForBuiltinRole(clusterName string, clusterConfig types.ClusterConfig, role teleport.Role) (auth.RoleSet, error) {
	switch role {
	case teleport.RoleAuth:
		return auth.FromSpec(
			role.String(),
			types.RoleSpecV3{
				Allow: types.RoleConditions{
					Namespaces: []string{types.Wildcard},
					Rules: []types.Rule{
						types.NewRule(types.KindAuthServer, auth.RW()),
					},
				},
			})
	case teleport.RoleProvisionToken:
		return auth.FromSpec(role.String(), types.RoleSpecV3{})
	case teleport.RoleNode:
		return auth.FromSpec(
			role.String(),
			types.RoleSpecV3{
				Allow: types.RoleConditions{
					Namespaces: []string{types.Wildcard},
					Rules: []types.Rule{
						types.NewRule(types.KindNode, auth.RW()),
						types.NewRule(types.KindSSHSession, auth.RW()),
						types.NewRule(types.KindEvent, auth.RW()),
						types.NewRule(types.KindProxy, auth.RO()),
						types.NewRule(types.KindCertAuthority, auth.ReadNoSecrets()),
						types.NewRule(types.KindUser, auth.RO()),
						types.NewRule(types.KindNamespace, auth.RO()),
						types.NewRule(types.KindRole, auth.RO()),
						types.NewRule(types.KindAuthServer, auth.RO()),
						types.NewRule(types.KindReverseTunnel, auth.RW()),
						types.NewRule(types.KindTunnelConnection, auth.RO()),
						types.NewRule(types.KindClusterConfig, auth.RO()),
						types.NewRule(types.KindSemaphore, auth.RW()),
					},
				},
			})
	case teleport.RoleApp:
		return auth.FromSpec(
			role.String(),
			types.RoleSpecV3{
				Allow: types.RoleConditions{
					Namespaces: []string{types.Wildcard},
					Rules: []types.Rule{
						types.NewRule(types.KindEvent, auth.RW()),
						types.NewRule(types.KindProxy, auth.RO()),
						types.NewRule(types.KindCertAuthority, auth.ReadNoSecrets()),
						types.NewRule(types.KindUser, auth.RO()),
						types.NewRule(types.KindNamespace, auth.RO()),
						types.NewRule(types.KindRole, auth.RO()),
						types.NewRule(types.KindAuthServer, auth.RO()),
						types.NewRule(types.KindReverseTunnel, auth.RW()),
						types.NewRule(types.KindTunnelConnection, auth.RO()),
						types.NewRule(types.KindClusterConfig, auth.RO()),
						types.NewRule(types.KindAppServer, auth.RW()),
						types.NewRule(types.KindWebSession, auth.RO()),
						types.NewRule(types.KindWebToken, auth.RO()),
						types.NewRule(types.KindJWT, auth.RW()),
					},
				},
			})
	case teleport.RoleDatabase:
		return auth.FromSpec(
			role.String(),
			types.RoleSpecV3{
				Allow: types.RoleConditions{
					Namespaces: []string{types.Wildcard},
					Rules: []types.Rule{
						types.NewRule(types.KindEvent, auth.RW()),
						types.NewRule(types.KindProxy, auth.RO()),
						types.NewRule(types.KindCertAuthority, auth.ReadNoSecrets()),
						types.NewRule(types.KindUser, auth.RO()),
						types.NewRule(types.KindNamespace, auth.RO()),
						types.NewRule(types.KindRole, auth.RO()),
						types.NewRule(types.KindAuthServer, auth.RO()),
						types.NewRule(types.KindReverseTunnel, auth.RW()),
						types.NewRule(types.KindTunnelConnection, auth.RO()),
						types.NewRule(types.KindClusterConfig, auth.RO()),
						types.NewRule(types.KindDatabaseServer, auth.RW()),
					},
				},
			})
	case teleport.RoleProxy:
		// if in recording mode, return a different set of permissions than regular
		// mode. recording proxy needs to be able to generate host certificates.
		if auth.IsRecordAtProxy(clusterConfig.GetSessionRecording()) {
			return auth.FromSpec(
				role.String(),
				types.RoleSpecV3{
					Allow: types.RoleConditions{
						Namespaces:    []string{types.Wildcard},
						ClusterLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
						Rules: []types.Rule{
							types.NewRule(types.KindProxy, auth.RW()),
							types.NewRule(types.KindOIDCRequest, auth.RW()),
							types.NewRule(types.KindSSHSession, auth.RW()),
							types.NewRule(types.KindSession, auth.RO()),
							types.NewRule(types.KindEvent, auth.RW()),
							types.NewRule(types.KindSAMLRequest, auth.RW()),
							types.NewRule(types.KindOIDC, auth.ReadNoSecrets()),
							types.NewRule(types.KindSAML, auth.ReadNoSecrets()),
							types.NewRule(types.KindGithub, auth.ReadNoSecrets()),
							types.NewRule(types.KindGithubRequest, auth.RW()),
							types.NewRule(types.KindNamespace, auth.RO()),
							types.NewRule(types.KindNode, auth.RO()),
							types.NewRule(types.KindAuthServer, auth.RO()),
							types.NewRule(types.KindReverseTunnel, auth.RO()),
							types.NewRule(types.KindCertAuthority, auth.ReadNoSecrets()),
							types.NewRule(types.KindUser, auth.RO()),
							types.NewRule(types.KindRole, auth.RO()),
							types.NewRule(types.KindClusterAuthPreference, auth.RO()),
							types.NewRule(types.KindClusterConfig, auth.RO()),
							types.NewRule(types.KindClusterName, auth.RO()),
							types.NewRule(types.KindStaticTokens, auth.RO()),
							types.NewRule(types.KindTunnelConnection, auth.RW()),
							types.NewRule(types.KindHostCert, auth.RW()),
							types.NewRule(types.KindRemoteCluster, auth.RO()),
							types.NewRule(types.KindSemaphore, auth.RW()),
							types.NewRule(types.KindAppServer, auth.RO()),
							types.NewRule(types.KindWebSession, auth.RW()),
							types.NewRule(types.KindWebToken, auth.RW()),
							types.NewRule(types.KindKubeService, auth.RW()),
							types.NewRule(types.KindDatabaseServer, auth.RO()),
							// this rule allows local proxy to update the remote cluster's host certificate authorities
							// during certificates renewal
							{
								Resources: []string{types.KindCertAuthority},
								Verbs:     []string{types.VerbCreate, types.VerbRead, types.VerbUpdate},
								// allow administrative access to the host certificate authorities
								// matching any cluster name except local
								Where: builder.And(
									builder.Equals(auth.CertAuthorityTypeExpr, builder.String(string(types.HostCA))),
									builder.Not(
										builder.Equals(
											auth.ResourceNameExpr,
											builder.String(clusterName),
										),
									),
								).String(),
							},
						},
					},
				})
		}
		return auth.FromSpec(
			role.String(),
			types.RoleSpecV3{
				Allow: types.RoleConditions{
					Namespaces:    []string{types.Wildcard},
					ClusterLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
					Rules: []types.Rule{
						types.NewRule(types.KindProxy, auth.RW()),
						types.NewRule(types.KindOIDCRequest, auth.RW()),
						types.NewRule(types.KindSSHSession, auth.RW()),
						types.NewRule(types.KindSession, auth.RO()),
						types.NewRule(types.KindEvent, auth.RW()),
						types.NewRule(types.KindSAMLRequest, auth.RW()),
						types.NewRule(types.KindOIDC, auth.ReadNoSecrets()),
						types.NewRule(types.KindSAML, auth.ReadNoSecrets()),
						types.NewRule(types.KindGithub, auth.ReadNoSecrets()),
						types.NewRule(types.KindGithubRequest, auth.RW()),
						types.NewRule(types.KindNamespace, auth.RO()),
						types.NewRule(types.KindNode, auth.RO()),
						types.NewRule(types.KindAuthServer, auth.RO()),
						types.NewRule(types.KindReverseTunnel, auth.RO()),
						types.NewRule(types.KindCertAuthority, auth.ReadNoSecrets()),
						types.NewRule(types.KindUser, auth.RO()),
						types.NewRule(types.KindRole, auth.RO()),
						types.NewRule(types.KindClusterAuthPreference, auth.RO()),
						types.NewRule(types.KindClusterConfig, auth.RO()),
						types.NewRule(types.KindClusterName, auth.RO()),
						types.NewRule(types.KindStaticTokens, auth.RO()),
						types.NewRule(types.KindTunnelConnection, auth.RW()),
						types.NewRule(types.KindRemoteCluster, auth.RO()),
						types.NewRule(types.KindSemaphore, auth.RW()),
						types.NewRule(types.KindAppServer, auth.RO()),
						types.NewRule(types.KindWebSession, auth.RW()),
						types.NewRule(types.KindWebToken, auth.RW()),
						types.NewRule(types.KindKubeService, auth.RW()),
						types.NewRule(types.KindDatabaseServer, auth.RO()),
						// this rule allows local proxy to update the remote cluster's host certificate authorities
						// during certificates renewal
						{
							Resources: []string{services.KindCertAuthority},
							Verbs:     []string{types.VerbCreate, types.VerbRead, types.VerbUpdate},
							// allow administrative access to the certificate authority names
							// matching any cluster name except local
							Where: builder.And(
								builder.Equals(auth.CertAuthorityTypeExpr, builder.String(string(types.HostCA))),
								builder.Not(
									builder.Equals(
										auth.ResourceNameExpr,
										builder.String(clusterName),
									),
								),
							).String(),
						},
					},
				},
			})
	case teleport.RoleWeb:
		return auth.FromSpec(
			role.String(),
			types.RoleSpecV3{
				Allow: types.RoleConditions{
					Namespaces: []string{types.Wildcard},
					Rules: []types.Rule{
						types.NewRule(types.KindWebSession, auth.RW()),
						types.NewRule(types.KindWebToken, auth.RW()),
						types.NewRule(types.KindSSHSession, auth.RW()),
						types.NewRule(types.KindAuthServer, auth.RO()),
						types.NewRule(types.KindUser, auth.RO()),
						types.NewRule(types.KindRole, auth.RO()),
						types.NewRule(types.KindNamespace, auth.RO()),
						types.NewRule(types.KindTrustedCluster, auth.RO()),
					},
				},
			})
	case teleport.RoleSignup:
		return auth.FromSpec(
			role.String(),
			types.RoleSpecV3{
				Allow: types.RoleConditions{
					Namespaces: []string{types.Wildcard},
					Rules: []types.Rule{
						types.NewRule(types.KindAuthServer, auth.RO()),
						types.NewRule(types.KindClusterAuthPreference, auth.RO()),
					},
				},
			})
	case teleport.RoleAdmin:
		return auth.FromSpec(
			role.String(),
			types.RoleSpecV3{
				Options: types.RoleOptions{
					MaxSessionTTL: services.MaxDuration(),
				},
				Allow: types.RoleConditions{
					Namespaces:    []string{types.Wildcard},
					Logins:        []string{},
					NodeLabels:    types.Labels{types.Wildcard: []string{types.Wildcard}},
					ClusterLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
					Rules: []types.Rule{
						types.NewRule(types.Wildcard, auth.RW()),
					},
				},
			})
	case teleport.RoleNop:
		return auth.FromSpec(
			role.String(),
			types.RoleSpecV3{
				Allow: types.RoleConditions{
					Namespaces: []string{},
					Rules:      []types.Rule{},
				},
			})
	case teleport.RoleKube:
		return auth.FromSpec(
			role.String(),
			types.RoleSpecV3{
				Allow: types.RoleConditions{
					Namespaces: []string{types.Wildcard},
					Rules: []types.Rule{
						types.NewRule(types.KindKubeService, auth.RW()),
						types.NewRule(types.KindEvent, auth.RW()),
						types.NewRule(types.KindCertAuthority, auth.ReadNoSecrets()),
						types.NewRule(types.KindClusterConfig, auth.RO()),
						types.NewRule(types.KindUser, auth.RO()),
						types.NewRule(types.KindRole, auth.RO()),
						types.NewRule(types.KindNamespace, auth.RO()),
					},
				},
			})
	}

	return nil, trace.NotFound("%q is not recognized", role.String())
}

func contextForBuiltinRole(clusterName string, clusterConfig types.ClusterConfig, r teleport.Role, username string) (*Context, error) {
	checker, err := GetCheckerForBuiltinRole(clusterName, clusterConfig, r)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user, err := types.NewUser(username)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user.SetRoles([]string{string(r)})
	return &Context{
		User:    user,
		Checker: BuiltinRoleSet{checker},
	}, nil
}

func contextForLocalUser(u LocalUser, identity auth.UserGetter, access auth.Access) (*Context, error) {
	// User has to be fetched to check if it's a blocked username
	user, err := identity.GetUser(u.Username, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roles, traits, err := auth.ExtractFromIdentity(identity, u.Identity)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	checker, err := auth.FetchRoles(roles, access, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// Override roles and traits from the local user based on the identity roles
	// and traits, this is done to prevent potential conflict. Imagine a scenairo
	// when SSO user has left the company, but local user entry remained with old
	// privileged roles. New user with the same name has been onboarded and would
	// have derived the roles from the stale user entry. This code prevents
	// that by extracting up to date identity traits and roles from the user's
	// certificate metadata.
	user.SetRoles(roles)
	user.SetTraits(traits)

	return &Context{
		User:    user,
		Checker: LocalUserRoleSet{checker},
	}, nil
}

type contextKey string

const (
	// ContextUser is a user set in the context of the request
	ContextUser contextKey = "teleport-user"
	// ContextClientAddr is a client address set in the context of the request
	ContextClientAddr contextKey = "client-addr"
)

// WithDelegator alias for backwards compatibility
var WithDelegator = client.WithDelegator

// clientUsername returns the username of a remote HTTP client making the call.
// If ctx didn't pass through auth middleware or did not come from an HTTP
// request, teleport.UserSystem is returned.
func clientUsername(ctx context.Context) string {
	userI := ctx.Value(ContextUser)
	userWithIdentity, ok := userI.(IdentityGetter)
	if !ok {
		return teleport.UserSystem
	}
	identity := userWithIdentity.GetIdentity()
	if identity.Username == "" {
		return teleport.UserSystem
	}
	return identity.Username
}

// LocalUser is a local user
type LocalUser struct {
	// Username is local username
	Username string
	// Identity is x509-derived identity used to build this user
	Identity tlsca.Identity
}

// GetIdentity returns client identity
func (l LocalUser) GetIdentity() tlsca.Identity {
	return l.Identity
}

// IdentityGetter returns client identity
type IdentityGetter interface {
	// GetIdentity  returns x509-derived identity of the user
	GetIdentity() tlsca.Identity
}

// WrapIdentity wraps identity to return identity getter function
type WrapIdentity tlsca.Identity

// GetIdentity returns identity
func (i WrapIdentity) GetIdentity() tlsca.Identity {
	return tlsca.Identity(i)
}

// BuiltinRole is the role of the Teleport service.
type BuiltinRole struct {
	// GetClusterConfig fetches cluster configuration.
	GetClusterConfig GetClusterConfigFunc

	// Role is the builtin role this username is associated with
	Role teleport.Role

	// Username is for authentication tracking purposes
	Username string

	// ClusterName is the name of the local cluster
	ClusterName string

	// Identity is source x509 used to build this role
	Identity tlsca.Identity
}

// IsServer returns true if the role is one of the builtin server roles.
func (r BuiltinRole) IsServer() bool {
	return r.Role == teleport.RoleProxy ||
		r.Role == teleport.RoleNode ||
		r.Role == teleport.RoleAuth ||
		r.Role == teleport.RoleApp ||
		r.Role == teleport.RoleKube ||
		r.Role == teleport.RoleDatabase
}

// GetServerID extracts the identity from the full name. The username
// extracted from the node's identity (x.509 certificate) is expected to
// consist of "<server-id>.<cluster-name>" so strip the cluster name suffix
// to get the server id.
//
// Note that as of right now Teleport expects server id to be a UUID4 but
// older Gravity clusters used to override it with strings like
// "192_168_1_1.<cluster-name>" so this code can't rely on it being
// UUID4 to account for clusters upgraded from older versions.
func (r BuiltinRole) GetServerID() string {
	return strings.TrimSuffix(r.Identity.Username, "."+r.ClusterName)
}

// GetIdentity returns client identity
func (r BuiltinRole) GetIdentity() tlsca.Identity {
	return r.Identity
}

// BuiltinRoleSet wraps a services.RoleSet. The type is used to determine if
// the role is builtin or not.
type BuiltinRoleSet struct {
	auth.RoleSet
}

// RemoteBuiltinRoleSet wraps a services.RoleSet. The type is used to determine if
// the role is a remote builtin or not.
type RemoteBuiltinRoleSet struct {
	auth.RoleSet
}

// LocalUserRoleSet wraps a services.RoleSet. This type is used to determine
// if the role is a local user or not.
type LocalUserRoleSet struct {
	auth.RoleSet
}

// RemoteUserRoleSet wraps a services.RoleSet. This type is used to determine
// if the role is a remote user or not.
type RemoteUserRoleSet struct {
	auth.RoleSet
}

// RemoteBuiltinRole is the role of the remote (service connecting via trusted cluster link)
// Teleport service.
type RemoteBuiltinRole struct {
	// Role is the builtin role of the user
	Role teleport.Role

	// Username is for authentication tracking purposes
	Username string

	// ClusterName is the name of the remote cluster.
	ClusterName string

	// Identity is source x509 used to build this role
	Identity tlsca.Identity
}

// GetIdentity returns client identity
func (r RemoteBuiltinRole) GetIdentity() tlsca.Identity {
	return r.Identity
}

// RemoteUser defines encoded remote user.
type RemoteUser struct {
	// Username is a name of the remote user
	Username string `json:"username"`

	// ClusterName is the name of the remote cluster
	// of the user.
	ClusterName string `json:"cluster_name"`

	// RemoteRoles is optional list of remote roles
	RemoteRoles []string `json:"remote_roles"`

	// Principals is a list of Unix logins.
	Principals []string `json:"principals"`

	// KubernetesGroups is a list of Kubernetes groups
	KubernetesGroups []string `json:"kubernetes_groups"`

	// KubernetesUsers is a list of Kubernetes users
	KubernetesUsers []string `json:"kubernetes_users"`

	// DatabaseNames is a list of database names a user can connect to.
	DatabaseNames []string `json:"database_names"`

	// DatabaseUsers is a list of database users a user can connect as.
	DatabaseUsers []string `json:"database_users"`

	// Identity is source x509 used to build this role
	Identity tlsca.Identity
}

// GetIdentity returns client identity
func (r RemoteUser) GetIdentity() tlsca.Identity {
	return r.Identity
}

// GetClusterConfigFunc returns a cached services.ClusterConfig.
type GetClusterConfigFunc func(opts ...auth.MarshalOption) (types.ClusterConfig, error)
