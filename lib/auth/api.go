/*
Copyright 2015-2020 Gravitational, Inc.

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
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/session"

	"github.com/gravitational/trace"
)

// Announcer specifies interface responsible for announcing presence
type Announcer interface {
	// UpsertNode registers node presence, permanently if ttl is 0 or
	// for the specified duration with second resolution if it's >= 1 second
	UpsertNode(s types.Server) (*types.KeepAlive, error)

	// UpsertProxy registers proxy presence, permanently if ttl is 0 or
	// for the specified duration with second resolution if it's >= 1 second
	UpsertProxy(s types.Server) error

	// UpsertAuthServer registers auth server presence, permanently if ttl is 0 or
	// for the specified duration with second resolution if it's >= 1 second
	UpsertAuthServer(s types.Server) error

	// UpsertKubeService registers kubernetes presence, permanently if ttl is 0
	// or for the specified duration with second resolution if it's >= 1 second
	UpsertKubeService(context.Context, types.Server) error

	// UpsertAppServer adds an application server.
	UpsertAppServer(context.Context, types.Server) (*types.KeepAlive, error)

	// UpsertDatabaseServer registers a database proxy server.
	UpsertDatabaseServer(context.Context, types.DatabaseServer) (*types.KeepAlive, error)
}

// KeepAliver creates new keep-alives
type KeepAliver interface {
	// NewKeepAliver returns a new instance of keep aliver
	NewKeepAliver(ctx context.Context) (types.KeepAliver, error)
}

// ReadAccessPoint is an API interface implemented by a certificate authority (CA)
type ReadAccessPoint interface {
	// Closer closes all the resources
	io.Closer

	// NewWatcher returns a new event watcher.
	NewWatcher(ctx context.Context, watch types.Watch) (types.Watcher, error)

	// GetReverseTunnels returns  a list of reverse tunnels
	GetReverseTunnels(opts ...MarshalOption) ([]types.ReverseTunnel, error)

	// GetClusterName returns cluster name
	GetClusterName(opts ...MarshalOption) (types.ClusterName, error)

	// GetClusterConfig returns cluster level configuration.
	GetClusterConfig(opts ...MarshalOption) (types.ClusterConfig, error)

	// GetNamespaces returns a list of namespaces
	GetNamespaces() ([]types.Namespace, error)

	// GetNamespace returns namespace by name
	GetNamespace(name string) (*types.Namespace, error)

	// GetNodes returns a list of registered servers for this cluster.
	GetNodes(namespace string, opts ...MarshalOption) ([]types.Server, error)

	// GetProxies returns a list of proxy servers registered in the cluster
	GetProxies() ([]types.Server, error)

	// GetAuthServers returns a list of auth servers registered in the cluster
	GetAuthServers() ([]types.Server, error)

	// GetCertAuthority returns cert authority by id
	GetCertAuthority(id types.CertAuthID, loadKeys bool, opts ...MarshalOption) (types.CertAuthority, error)

	// GetCertAuthorities returns a list of cert authorities
	GetCertAuthorities(caType types.CertAuthType, loadKeys bool, opts ...MarshalOption) ([]types.CertAuthority, error)

	// GetUser returns a types.User for this cluster.
	GetUser(name string, withSecrets bool) (types.User, error)

	// GetUsers returns a list of local users registered with this domain
	GetUsers(withSecrets bool) ([]types.User, error)

	// GetRole returns role by name
	GetRole(name string) (types.Role, error)

	// GetRoles returns a list of roles
	GetRoles() ([]types.Role, error)

	// GetAllTunnelConnections returns all tunnel connections
	GetAllTunnelConnections(opts ...MarshalOption) ([]types.TunnelConnection, error)

	// GetTunnelConnections returns tunnel connections for a given cluster
	GetTunnelConnections(clusterName string, opts ...MarshalOption) ([]types.TunnelConnection, error)

	// GetAppServers gets all application servers.
	GetAppServers(ctx context.Context, namespace string, opts ...MarshalOption) ([]types.Server, error)

	// GetAppSession gets an application web session.
	GetAppSession(context.Context, types.GetAppSessionRequest) (types.WebSession, error)

	// GetWebSession gets a web session for the given request
	GetWebSession(context.Context, types.GetWebSessionRequest) (types.WebSession, error)

	// GetWebToken gets a web token for the given request
	GetWebToken(context.Context, types.GetWebTokenRequest) (types.WebToken, error)

	// GetRemoteClusters returns a list of remote clusters
	GetRemoteClusters(opts ...MarshalOption) ([]types.RemoteCluster, error)

	// GetRemoteCluster returns a remote cluster by name
	GetRemoteCluster(clusterName string) (types.RemoteCluster, error)

	// GetKubeServices returns a list of kubernetes services registered in the cluster
	GetKubeServices(context.Context) ([]types.Server, error)

	// GetDatabaseServers returns all registered database proxy servers.
	GetDatabaseServers(ctx context.Context, namespace string, opts ...MarshalOption) ([]types.DatabaseServer, error)
}

// AccessPoint is an API interface implemented by a certificate authority (CA)
type AccessPoint interface {
	// ReadAccessPoint provides methods to read data
	ReadAccessPoint
	// Announcer adds methods used to announce presence
	Announcer
	// Streamer creates and manages audit streams
	events.Streamer

	// Semaphores provides semaphore operations
	types.Semaphores

	// UpsertTunnelConnection upserts tunnel connection
	UpsertTunnelConnection(conn types.TunnelConnection) error

	// DeleteTunnelConnection deletes tunnel connection
	DeleteTunnelConnection(clusterName, connName string) error
}

// ClientAccessPoint represents client side AccessPoint
type ClientAccessPoint interface {
	AccessPoint
	KeepAliver
}

// AccessCache is a subset of the interface working on the certificate authorities
type AccessCache interface {
	// GetCertAuthority returns cert authority by id
	GetCertAuthority(id types.CertAuthID, loadKeys bool, opts ...MarshalOption) (types.CertAuthority, error)

	// GetCertAuthorities returns a list of cert authorities
	GetCertAuthorities(caType types.CertAuthType, loadKeys bool, opts ...MarshalOption) ([]types.CertAuthority, error)

	// GetClusterConfig returns cluster level configuration.
	GetClusterConfig(opts ...MarshalOption) (types.ClusterConfig, error)

	// GetClusterName gets the name of the cluster from the backend.
	GetClusterName(opts ...MarshalOption) (types.ClusterName, error)
}

// Cache is a subset of the auth interface handling
// access to the discovery API and static tokens
type Cache interface {
	ReadAccessPoint

	// GetStaticTokens gets the list of static tokens used to provision nodes.
	GetStaticTokens() (types.StaticTokens, error)

	// GetTokens returns all active (non-expired) provisioning tokens
	GetTokens(opts ...MarshalOption) ([]types.ProvisionToken, error)

	// GetToken finds and returns token by ID
	GetToken(token string) (types.ProvisionToken, error)

	// NewWatcher returns a new event watcher
	NewWatcher(ctx context.Context, watch types.Watch) (types.Watcher, error)
}

// NewWrapper returns new access point wrapper
func NewWrapper(base ClientAccessPoint, cache ReadAccessPoint) ClientAccessPoint {
	return &Wrapper{
		NoCache:         base,
		ReadAccessPoint: cache,
	}
}

// Wrapper wraps access point and auth cache in one client
// so that reads of cached values can be intercepted.
type Wrapper struct {
	ReadAccessPoint
	NoCache ClientAccessPoint
}

// ResumeAuditStream resumes existing audit stream
func (w *Wrapper) ResumeAuditStream(ctx context.Context, sid session.ID, uploadID string) (events.Stream, error) {
	return w.NoCache.ResumeAuditStream(ctx, sid, uploadID)
}

// CreateAuditStream creates new audit stream
func (w *Wrapper) CreateAuditStream(ctx context.Context, sid session.ID) (events.Stream, error) {
	return w.NoCache.CreateAuditStream(ctx, sid)
}

// Close closes all associated resources
func (w *Wrapper) Close() error {
	err := w.NoCache.Close()
	err2 := w.ReadAccessPoint.Close()
	return trace.NewAggregate(err, err2)
}

// UpsertNode is part of auth.AccessPoint implementation
func (w *Wrapper) UpsertNode(s types.Server) (*types.KeepAlive, error) {
	return w.NoCache.UpsertNode(s)
}

// UpsertAuthServer is part of auth.AccessPoint implementation
func (w *Wrapper) UpsertAuthServer(s types.Server) error {
	return w.NoCache.UpsertAuthServer(s)
}

// NewKeepAliver returns a new instance of keep aliver
func (w *Wrapper) NewKeepAliver(ctx context.Context) (types.KeepAliver, error) {
	return w.NoCache.NewKeepAliver(ctx)
}

// UpsertProxy is part of auth.AccessPoint implementation
func (w *Wrapper) UpsertProxy(s types.Server) error {
	return w.NoCache.UpsertProxy(s)
}

// UpsertTunnelConnection is a part of auth.AccessPoint implementation
func (w *Wrapper) UpsertTunnelConnection(conn types.TunnelConnection) error {
	return w.NoCache.UpsertTunnelConnection(conn)
}

// DeleteTunnelConnection is a part of auth.AccessPoint implementation
func (w *Wrapper) DeleteTunnelConnection(clusterName, connName string) error {
	return w.NoCache.DeleteTunnelConnection(clusterName, connName)
}

// AcquireSemaphore acquires lease with requested resources from semaphore
func (w *Wrapper) AcquireSemaphore(ctx context.Context, params types.AcquireSemaphoreRequest) (*types.SemaphoreLease, error) {
	return w.NoCache.AcquireSemaphore(ctx, params)
}

// KeepAliveSemaphoreLease updates semaphore lease
func (w *Wrapper) KeepAliveSemaphoreLease(ctx context.Context, lease types.SemaphoreLease) error {
	return w.NoCache.KeepAliveSemaphoreLease(ctx, lease)
}

// CancelSemaphoreLease cancels semaphore lease early
func (w *Wrapper) CancelSemaphoreLease(ctx context.Context, lease types.SemaphoreLease) error {
	return w.NoCache.CancelSemaphoreLease(ctx, lease)
}

// GetSemaphores returns a list of semaphores matching supplied filter.
func (w *Wrapper) GetSemaphores(ctx context.Context, filter types.SemaphoreFilter) ([]types.Semaphore, error) {
	return w.NoCache.GetSemaphores(ctx, filter)
}

// DeleteSemaphore deletes a semaphore matching supplied filter.
func (w *Wrapper) DeleteSemaphore(ctx context.Context, filter types.SemaphoreFilter) error {
	return w.NoCache.DeleteSemaphore(ctx, filter)
}

// UpsertKubeService is part of auth.AccessPoint implementation
func (w *Wrapper) UpsertKubeService(ctx context.Context, s types.Server) error {
	return w.NoCache.UpsertKubeService(ctx, s)
}

// UpsertAppServer adds an application server.
func (w *Wrapper) UpsertAppServer(ctx context.Context, server types.Server) (*types.KeepAlive, error) {
	return w.NoCache.UpsertAppServer(ctx, server)
}

// UpsertDatabaseServer registers a database proxy server.
func (w *Wrapper) UpsertDatabaseServer(ctx context.Context, server types.DatabaseServer) (*types.KeepAlive, error) {
	return w.NoCache.UpsertDatabaseServer(ctx, server)
}

// EncodeClusterName encodes cluster name in the SNI hostname
func EncodeClusterName(clusterName string) string {
	// hex is used to hide "." that will prevent wildcard *. entry to match
	return fmt.Sprintf("%v.%v", hex.EncodeToString([]byte(clusterName)), teleport.APIDomain)
}

// DecodeClusterName decodes cluster name, returns NotFound
// if no cluster name is encoded (empty subdomain),
// so servers can detect cases when no server name passed
// returns BadParameter if encoding does not match
func DecodeClusterName(serverName string) (string, error) {
	if serverName == teleport.APIDomain {
		return "", trace.NotFound("no cluster name is encoded")
	}
	const suffix = "." + teleport.APIDomain
	if !strings.HasSuffix(serverName, suffix) {
		return "", trace.NotFound("no cluster name is encoded")
	}
	clusterName := strings.TrimSuffix(serverName, suffix)

	decoded, err := hex.DecodeString(clusterName)
	if err != nil {
		return "", trace.BadParameter("failed to decode cluster name: %v", err)
	}
	return string(decoded), nil
}
