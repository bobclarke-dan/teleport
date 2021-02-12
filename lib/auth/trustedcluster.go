/*
Copyright 2017 Gravitational, Inc.

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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/roundtrip"
	"github.com/gravitational/trace"
)

// UpsertTrustedCluster creates or toggles a Trusted Cluster relationship.
func (a *Server) UpsertTrustedCluster(ctx context.Context, trustedCluster types.TrustedCluster) (types.TrustedCluster, error) {
	var exists bool

	// It is recommended to omit trusted cluster name because the trusted cluster name
	// is updated to the roots cluster name during the handshake with the root cluster.
	var existingCluster types.TrustedCluster
	if trustedCluster.GetName() != "" {
		var err error
		if existingCluster, err = a.Services.ServerPresence.GetTrustedCluster(trustedCluster.GetName()); err == nil {
			exists = true
		}
	}

	enable := trustedCluster.GetEnabled()

	// If the trusted cluster already exists in the backend, make sure it's a
	// valid state change client is trying to make.
	if exists {
		if err := existingCluster.CanChangeStateTo(trustedCluster); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// change state
	switch {
	case exists == true && enable == true:
		log.Debugf("Enabling existing Trusted Cluster relationship.")

		if err := a.activateCertAuthority(trustedCluster); err != nil {
			if trace.IsNotFound(err) {
				return nil, trace.BadParameter("enable only supported for Trusted Clusters created with Teleport 2.3 and above")
			}
			return nil, trace.Wrap(err)
		}

		if err := a.createReverseTunnel(trustedCluster); err != nil {
			return nil, trace.Wrap(err)
		}
	case exists == true && enable == false:
		log.Debugf("Disabling existing Trusted Cluster relationship.")

		if err := a.deactivateCertAuthority(trustedCluster); err != nil {
			if trace.IsNotFound(err) {
				return nil, trace.BadParameter("enable only supported for Trusted Clusters created with Teleport 2.3 and above")
			}
			return nil, trace.Wrap(err)
		}

		if err := a.Services.DeleteReverseTunnel(trustedCluster.GetName()); err != nil {
			return nil, trace.Wrap(err)
		}
	case exists == false && enable == true:
		log.Debugf("Creating enabled Trusted Cluster relationship.")

		if err := a.checkLocalRoles(trustedCluster.GetRoleMap()); err != nil {
			return nil, trace.Wrap(err)
		}

		remoteCAs, err := a.establishTrust(trustedCluster)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		// Force name of the trusted cluster resource
		// to be equal to the name of the remote cluster it is connecting to.
		trustedCluster.SetName(remoteCAs[0].GetClusterName())

		if err := a.addCertAuthorities(trustedCluster, remoteCAs); err != nil {
			return nil, trace.Wrap(err)
		}

		if err := a.createReverseTunnel(trustedCluster); err != nil {
			return nil, trace.Wrap(err)
		}

	case exists == false && enable == false:
		log.Debugf("Creating disabled Trusted Cluster relationship.")

		if err := a.checkLocalRoles(trustedCluster.GetRoleMap()); err != nil {
			return nil, trace.Wrap(err)
		}

		remoteCAs, err := a.establishTrust(trustedCluster)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		// Force name to the name of the trusted cluster.
		trustedCluster.SetName(remoteCAs[0].GetClusterName())

		if err := a.addCertAuthorities(trustedCluster, remoteCAs); err != nil {
			return nil, trace.Wrap(err)
		}

		if err := a.deactivateCertAuthority(trustedCluster); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	tc, err := a.Services.ServerPresence.UpsertTrustedCluster(ctx, trustedCluster)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := a.emitter.EmitAuditEvent(ctx, &events.TrustedClusterCreate{
		Metadata: events.Metadata{
			Type: events.TrustedClusterCreateEvent,
			Code: events.TrustedClusterCreateCode,
		},
		UserMetadata: events.UserMetadata{
			User: clientUsername(ctx),
		},
		ResourceMetadata: events.ResourceMetadata{
			Name: trustedCluster.GetName(),
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit trusted cluster create event.")
	}

	return tc, nil
}

func (a *Server) checkLocalRoles(roleMap types.RoleMap) error {
	for _, mapping := range roleMap {
		for _, localRole := range mapping.Local {
			// expansion means dynamic mapping is in place,
			// so local role is undefined
			if utils.ContainsExpansion(localRole) {
				continue
			}
			_, err := a.GetRole(localRole)
			if err != nil {
				if trace.IsNotFound(err) {
					return trace.NotFound("a role %q referenced in a mapping %v:%v is not defined", localRole, mapping.Remote, mapping.Local)
				}
				return trace.Wrap(err)
			}
		}
	}
	return nil
}

// DeleteTrustedCluster removes types.CertAuthority, types.ReverseTunnel,
// and types.TrustedCluster resources.
func (a *Server) DeleteTrustedCluster(ctx context.Context, name string) error {
	cn, err := a.GetClusterName()
	if err != nil {
		return trace.Wrap(err)
	}

	// This check ensures users are not deleting their root/own cluster.
	if cn.GetClusterName() == name {
		return trace.BadParameter("trusted cluster %q is the name of this root cluster and cannot be removed.", name)
	}

	if err := a.Services.ServerTrust.DeleteCertAuthority(types.CertAuthID{Type: types.HostCA, DomainName: name}); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}

	if err := a.Services.ServerTrust.DeleteCertAuthority(types.CertAuthID{Type: types.UserCA, DomainName: name}); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}

	if err := a.Services.DeleteReverseTunnel(name); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}

	if err := a.Services.ServerPresence.DeleteTrustedCluster(ctx, name); err != nil {
		return trace.Wrap(err)
	}

	if err := a.emitter.EmitAuditEvent(ctx, &events.TrustedClusterDelete{
		Metadata: events.Metadata{
			Type: events.TrustedClusterDeleteEvent,
			Code: events.TrustedClusterDeleteCode,
		},
		UserMetadata: events.UserMetadata{
			User: clientUsername(ctx),
		},
		ResourceMetadata: events.ResourceMetadata{
			Name: name,
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit trusted cluster delete event.")
	}

	return nil
}

func (a *Server) establishTrust(trustedCluster types.TrustedCluster) ([]types.CertAuthority, error) {
	var localCertAuthorities []types.CertAuthority

	domainName, err := a.GetDomainName()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// get a list of certificate authorities for this auth server
	allLocalCAs, err := a.GetCertAuthorities(types.HostCA, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	for _, lca := range allLocalCAs {
		if lca.GetClusterName() == domainName {
			localCertAuthorities = append(localCertAuthorities, lca)
		}
	}

	// create a request to validate a trusted cluster (token and local certificate authorities)
	validateRequest := ValidateTrustedClusterRequest{
		Token: trustedCluster.GetToken(),
		CAs:   localCertAuthorities,
	}

	// log the local certificate authorities that we are sending
	log.Debugf("Sending validate request; token=%v, CAs=%v", validateRequest.Token, validateRequest.CAs)

	// send the request to the remote auth server via the proxy
	validateResponse, err := a.sendValidateRequestToProxy(trustedCluster.GetProxyAddress(), &validateRequest)
	if err != nil {
		log.Error(err)
		if strings.Contains(err.Error(), "x509") {
			return nil, trace.AccessDenied("the trusted cluster uses misconfigured HTTP/TLS certificate.")
		}
		return nil, trace.Wrap(err)
	}

	// log the remote certificate authorities we are adding
	log.Debugf("Received validate response; CAs=%v", validateResponse.CAs)

	for _, ca := range validateResponse.CAs {
		for _, keyPair := range ca.GetTLSKeyPairs() {
			cert, err := tlsca.ParseCertificatePEM(keyPair.Cert)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			remoteClusterName, err := tlsca.ClusterName(cert.Subject)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			if remoteClusterName == domainName {
				return nil, trace.BadParameter("remote cluster name can not be the same as local cluster name")
			}
			// TODO(klizhentas) in 2.5.0 prohibit adding trusted cluster resource name
			// different from cluster name (we had no way of checking this before x509,
			// because SSH CA was a public key, not a cert with metadata)
		}
	}

	return validateResponse.CAs, nil
}

func (a *Server) addCertAuthorities(trustedCluster types.TrustedCluster, remoteCAs []types.CertAuthority) error {
	// the remote auth server has verified our token. add the
	// remote certificate authority to our backend
	for _, remoteCertAuthority := range remoteCAs {
		// change the name of the remote ca to the name of the trusted cluster
		remoteCertAuthority.SetName(trustedCluster.GetName())

		// wipe out roles sent from the remote cluster and set roles from the trusted cluster
		remoteCertAuthority.SetRoles(nil)
		if remoteCertAuthority.GetType() == types.UserCA {
			for _, r := range trustedCluster.GetRoles() {
				remoteCertAuthority.AddRole(r)
			}
			remoteCertAuthority.SetRoleMap(trustedCluster.GetRoleMap())
		}

		// we use create here instead of upsert to prevent people from wiping out
		// their own ca if it has the same name as the remote ca
		err := a.Services.ServerTrust.CreateCertAuthority(remoteCertAuthority)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// DeleteRemoteCluster deletes remote cluster resource, all certificate authorities
// associated with it
func (a *Server) DeleteRemoteCluster(clusterName string) error {
	// To make sure remote cluster exists - to protect against random
	// clusterName requests (e.g. when clusterName is set to local cluster name)
	_, err := a.Services.ServerPresence.GetRemoteCluster(clusterName)
	if err != nil {
		return trace.Wrap(err)
	}
	// delete cert authorities associated with the cluster
	err = a.Services.ServerTrust.DeleteCertAuthority(types.CertAuthID{
		Type:       types.HostCA,
		DomainName: clusterName,
	})
	if err != nil {
		// this method could have succeeded on the first call,
		// but then if the remote cluster resource could not be deleted
		// it would be impossible to delete the cluster after then
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	// there should be no User CA in trusted clusters on the main cluster side
	// per standard automation but clean up just in case
	err = a.Services.ServerTrust.DeleteCertAuthority(types.CertAuthID{
		Type:       types.UserCA,
		DomainName: clusterName,
	})
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return a.Services.ServerPresence.DeleteRemoteCluster(clusterName)
}

// GetRemoteCluster returns remote cluster by name
func (a *Server) GetRemoteCluster(clusterName string) (types.RemoteCluster, error) {
	// To make sure remote cluster exists - to protect against random
	// clusterName requests (e.g. when clusterName is set to local cluster name)
	remoteCluster, err := a.Services.ServerPresence.GetRemoteCluster(clusterName)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.updateRemoteClusterStatus(remoteCluster); err != nil {
		return nil, trace.Wrap(err)
	}
	return remoteCluster, nil
}

func (a *Server) updateRemoteClusterStatus(remoteCluster types.RemoteCluster) error {
	ctx := context.TODO()
	clusterConfig, err := a.GetClusterConfig()
	if err != nil {
		return trace.Wrap(err)
	}
	keepAliveCountMax := clusterConfig.GetKeepAliveCountMax()
	keepAliveInterval := clusterConfig.GetKeepAliveInterval()

	// fetch tunnel connections for the cluster to update runtime status
	connections, err := a.GetTunnelConnections(remoteCluster.GetName())
	if err != nil {
		return trace.Wrap(err)
	}
	lastConn, err := services.LatestTunnelConnection(connections)
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		// No tunnel connections are known, mark the cluster offline (if it
		// wasn't already).
		if remoteCluster.GetConnectionStatus() != teleport.RemoteClusterStatusOffline {
			remoteCluster.SetConnectionStatus(teleport.RemoteClusterStatusOffline)
			if err := a.Services.UpdateRemoteCluster(ctx, remoteCluster); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}

	offlineThreshold := time.Duration(keepAliveCountMax) * keepAliveInterval
	tunnelStatus := services.TunnelConnectionStatus(a.clock, lastConn, offlineThreshold)

	// Update remoteCluster based on lastConn. If anything changed, update it
	// in the backend too.
	prevConnectionStatus := remoteCluster.GetConnectionStatus()
	prevLastHeartbeat := remoteCluster.GetLastHeartbeat()
	remoteCluster.SetConnectionStatus(tunnelStatus)
	// Only bump LastHeartbeat if it's newer.
	if lastConn.GetLastHeartbeat().After(prevLastHeartbeat) {
		remoteCluster.SetLastHeartbeat(lastConn.GetLastHeartbeat().UTC())
	}
	if prevConnectionStatus != remoteCluster.GetConnectionStatus() || !prevLastHeartbeat.Equal(remoteCluster.GetLastHeartbeat()) {
		if err := a.Services.UpdateRemoteCluster(ctx, remoteCluster); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// GetRemoteClusters returns remote clusters with updated statuses
func (a *Server) GetRemoteClusters(opts ...services.MarshalOption) ([]types.RemoteCluster, error) {
	// To make sure remote cluster exists - to protect against random
	// clusterName requests (e.g. when clusterName is set to local cluster name)
	remoteClusters, err := a.Services.ServerPresence.GetRemoteClusters(opts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	for i := range remoteClusters {
		if err := a.updateRemoteClusterStatus(remoteClusters[i]); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return remoteClusters, nil
}

func (a *Server) validateTrustedCluster(validateRequest *ValidateTrustedClusterRequest) (resp *ValidateTrustedClusterResponse, err error) {
	defer func() {
		if err != nil {
			log.WithError(err).Info("Trusted cluster validation failed")
		}
	}()

	log.Debugf("Received validate request: token=%v, CAs=%v", validateRequest.Token, validateRequest.CAs)

	domainName, err := a.GetDomainName()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// validate that we generated the token
	tokenLabels, err := a.validateTrustedClusterToken(validateRequest.Token)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// add remote cluster resource to keep track of the remote cluster
	var remoteClusterName string
	for _, certAuthority := range validateRequest.CAs {
		// don't add a ca with the same as as local cluster name
		if certAuthority.GetName() == domainName {
			return nil, trace.AccessDenied("remote certificate authority has same name as cluster certificate authority: %v", domainName)
		}
		remoteClusterName = certAuthority.GetName()
	}
	remoteCluster, err := services.NewRemoteCluster(remoteClusterName)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(tokenLabels) != 0 {
		meta := remoteCluster.GetMetadata()
		meta.Labels = utils.CopyStringsMap(tokenLabels)
		remoteCluster.SetMetadata(meta)
	}

	err = a.Services.CreateRemoteCluster(remoteCluster)
	if err != nil {
		if !trace.IsAlreadyExists(err) {
			return nil, trace.Wrap(err)
		}
	}

	// token has been validated, upsert the given certificate authority
	for _, certAuthority := range validateRequest.CAs {
		err = a.Services.ServerTrust.UpsertCertAuthority(certAuthority)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// export local cluster certificate authority and return it to the cluster
	validateResponse := ValidateTrustedClusterResponse{
		CAs: []types.CertAuthority{},
	}
	for _, caType := range []types.CertAuthType{types.HostCA, types.UserCA} {
		certAuthority, err := a.GetCertAuthority(
			types.CertAuthID{Type: caType, DomainName: domainName},
			false, services.SkipValidation())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		validateResponse.CAs = append(validateResponse.CAs, certAuthority)
	}

	// log the local certificate authorities we are sending
	log.Debugf("Sending validate response: CAs=%v", validateResponse.CAs)

	return &validateResponse, nil
}

func (a *Server) validateTrustedClusterToken(token string) (map[string]string, error) {
	roles, labels, err := a.ValidateToken(token)
	if err != nil {
		return nil, trace.AccessDenied("the remote server denied access: invalid cluster token")
	}

	if !roles.Include(teleport.RoleTrustedCluster) && !roles.Include(teleport.LegacyClusterTokenType) {
		return nil, trace.AccessDenied("role does not match")
	}

	return labels, nil
}

func (a *Server) sendValidateRequestToProxy(host string, validateRequest *ValidateTrustedClusterRequest) (*ValidateTrustedClusterResponse, error) {
	proxyAddr := url.URL{
		Scheme: "https",
		Host:   host,
	}

	opts := []roundtrip.ClientParam{
		roundtrip.SanitizerEnabled(true),
	}

	if lib.IsInsecureDevMode() {
		log.Warn("The setting insecureSkipVerify is used to communicate with proxy. Make sure you intend to run Teleport in insecure mode!")

		// Get the default transport, this allows picking up proxy from the
		// environment.
		tr, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, trace.BadParameter("unable to get default transport")
		}

		// Disable certificate checking while in debug mode.
		tlsConfig := utils.TLSConfig(a.cipherSuites)
		tlsConfig.InsecureSkipVerify = true
		tr.TLSClientConfig = tlsConfig

		insecureWebClient := &http.Client{
			Transport: tr,
		}
		opts = append(opts, roundtrip.HTTPClient(insecureWebClient))
	}

	clt, err := roundtrip.NewClient(proxyAddr.String(), teleport.WebAPIVersion, opts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	validateRequestRaw, err := validateRequest.ToRaw()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	out, err := httplib.ConvertResponse(clt.PostJSON(context.TODO(), clt.Endpoint("webapi", "trustedclusters", "validate"), validateRequestRaw))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var validateResponseRaw *ValidateTrustedClusterResponseRaw
	err = json.Unmarshal(out.Bytes(), &validateResponseRaw)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	validateResponse, err := validateResponseRaw.ToNative()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return validateResponse, nil
}

type ValidateTrustedClusterRequest struct {
	Token string                `json:"token"`
	CAs   []types.CertAuthority `json:"certificate_authorities"`
}

func (v *ValidateTrustedClusterRequest) ToRaw() (*ValidateTrustedClusterRequestRaw, error) {
	cas := [][]byte{}

	for _, certAuthority := range v.CAs {
		data, err := services.MarshalCertAuthority(certAuthority)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		cas = append(cas, data)
	}

	return &ValidateTrustedClusterRequestRaw{
		Token: v.Token,
		CAs:   cas,
	}, nil
}

type ValidateTrustedClusterRequestRaw struct {
	Token string   `json:"token"`
	CAs   [][]byte `json:"certificate_authorities"`
}

func (v *ValidateTrustedClusterRequestRaw) ToNative() (*ValidateTrustedClusterRequest, error) {
	cas := []types.CertAuthority{}

	for _, rawCertAuthority := range v.CAs {
		certAuthority, err := services.UnmarshalCertAuthority(rawCertAuthority)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		cas = append(cas, certAuthority)
	}

	return &ValidateTrustedClusterRequest{
		Token: v.Token,
		CAs:   cas,
	}, nil
}

type ValidateTrustedClusterResponse struct {
	CAs []types.CertAuthority `json:"certificate_authorities"`
}

func (v *ValidateTrustedClusterResponse) ToRaw() (*ValidateTrustedClusterResponseRaw, error) {
	cas := [][]byte{}

	for _, certAuthority := range v.CAs {
		data, err := services.MarshalCertAuthority(certAuthority)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		cas = append(cas, data)
	}

	return &ValidateTrustedClusterResponseRaw{
		CAs: cas,
	}, nil
}

type ValidateTrustedClusterResponseRaw struct {
	CAs [][]byte `json:"certificate_authorities"`
}

func (v *ValidateTrustedClusterResponseRaw) ToNative() (*ValidateTrustedClusterResponse, error) {
	cas := []types.CertAuthority{}

	for _, rawCertAuthority := range v.CAs {
		certAuthority, err := services.UnmarshalCertAuthority(rawCertAuthority)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		cas = append(cas, certAuthority)
	}

	return &ValidateTrustedClusterResponse{
		CAs: cas,
	}, nil
}

// activateCertAuthority will activate both the user and host certificate
// authority given in the types.TrustedCluster resource.
func (a *Server) activateCertAuthority(t types.TrustedCluster) error {
	err := a.Services.ServerTrust.ActivateCertAuthority(types.CertAuthID{Type: types.UserCA, DomainName: t.GetName()})
	if err != nil {
		return trace.Wrap(err)
	}

	return trace.Wrap(a.Services.ServerTrust.ActivateCertAuthority(types.CertAuthID{Type: types.HostCA, DomainName: t.GetName()}))
}

// deactivateCertAuthority will deactivate both the user and host certificate
// authority given in the types.TrustedCluster resource.
func (a *Server) deactivateCertAuthority(t types.TrustedCluster) error {
	err := a.Services.ServerTrust.DeactivateCertAuthority(types.CertAuthID{Type: types.UserCA, DomainName: t.GetName()})
	if err != nil {
		return trace.Wrap(err)
	}

	return trace.Wrap(a.Services.ServerTrust.DeactivateCertAuthority(types.CertAuthID{Type: types.HostCA, DomainName: t.GetName()}))
}

// createReverseTunnel will create a types.ReverseTunnel givenin the
// types.TrustedCluster resource.
func (a *Server) createReverseTunnel(t types.TrustedCluster) error {
	reverseTunnel := types.NewReverseTunnel(
		t.GetName(),
		[]string{t.GetReverseTunnelAddress()},
	)
	return trace.Wrap(a.Services.UpsertReverseTunnel(reverseTunnel))
}

// ValidateTrustedCluster checks and sets Trusted Cluster defaults
func ValidateTrustedCluster(tc TrustedCluster) error {
	if err := tc.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	// we are not mentioning Roles parameter because we are deprecating it
	if len(tc.GetRoles()) == 0 && len(tc.GetRoleMap()) == 0 {
		if err := modules.GetModules().EmptyRolesHandler(); err != nil {
			return trace.Wrap(err)
		}
		// OSS teleport uses 'admin' by default:
		tc.SetRoleMap(RoleMap{
			RoleMapping{
				Remote: teleport.AdminRoleName,
				Local:  []string{teleport.AdminRoleName},
			},
		})
	}

	if _, err := parseRoleMap(tc.GetRoleMap()); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// RoleMapToString prints user friendly representation of role mapping
func RoleMapToString(r RoleMap) string {
	values, err := parseRoleMap(r)
	if err != nil {
		return fmt.Sprintf("<failed to parse: %v", err)
	}
	if len(values) != 0 {
		return fmt.Sprintf("%v", values)
	}
	return "<empty>"
}

func parseRoleMap(r RoleMap) (map[string][]string, error) {
	directMatch := make(map[string][]string)
	for i := range r {
		roleMap := r[i]
		if roleMap.Remote == "" {
			return nil, trace.BadParameter("missing 'remote' parameter for role_map")
		}
		_, err := utils.ReplaceRegexp(roleMap.Remote, "", "")
		if trace.IsBadParameter(err) {
			return nil, trace.BadParameter("failed to parse 'remote' parameter for role_map: %v", err.Error())
		}
		if len(roleMap.Local) == 0 {
			return nil, trace.BadParameter("missing 'local' parameter for 'role_map'")
		}
		for _, local := range roleMap.Local {
			if local == "" {
				return nil, trace.BadParameter("missing 'local' property of 'role_map' entry")
			}
			if local == Wildcard {
				return nil, trace.BadParameter("wildcard value is not supported for 'local' property of 'role_map' entry")
			}
		}
		_, ok := directMatch[roleMap.Remote]
		if ok {
			return nil, trace.BadParameter("remote role '%v' match is already specified", roleMap.Remote)
		}
		directMatch[roleMap.Remote] = roleMap.Local
	}
	return directMatch, nil
}

// MapRoles maps local roles to remote roles
func MapRoles(r RoleMap, remoteRoles []string) ([]string, error) {
	_, err := parseRoleMap(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var outRoles []string
	// when no remote roles are specified, assume that
	// there is a single empty remote role (that should match wildcards)
	if len(remoteRoles) == 0 {
		remoteRoles = []string{""}
	}
	for _, mapping := range r {
		expression := mapping.Remote
		for _, remoteRole := range remoteRoles {
			// never map default implicit role, it is always
			// added by default
			if remoteRole == constants.DefaultImplicitRole {
				continue
			}
			for _, replacementRole := range mapping.Local {
				replacement, err := utils.ReplaceRegexp(expression, replacementRole, remoteRole)
				switch {
				case err == nil:
					// empty replacement can occur when $2 expand refers
					// to non-existing capture group in match expression
					if replacement != "" {
						outRoles = append(outRoles, replacement)
					}
				case trace.IsNotFound(err):
					continue
				default:
					return nil, trace.Wrap(err)
				}
			}
		}
	}
	return outRoles, nil
}

// TrustedClusterSpecSchemaTemplate is a template for trusted cluster schema
const TrustedClusterSpecSchemaTemplate = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
	  "enabled": {"type": "boolean"},
	  "roles": {
		"type": "array",
		"items": {
		  "type": "string"
		}
	  },
	  "role_map": %v,
	  "token": {"type": "string"},
	  "web_proxy_addr": {"type": "string"},
	  "tunnel_addr": {"type": "string"}%v
	}
  }`

// RoleMapSchema is a schema for role mappings of trusted clusters
const RoleMapSchema = `{
	"type": "array",
	"items": {
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
		"local": {
		  "type": "array",
		  "items": {
			 "type": "string"
		  }
		},
		"remote": {"type": "string"}
	  }
	}
  }`

// GetTrustedClusterSchema returns the schema with optionally injected
// schema for extensions.
func GetTrustedClusterSchema(extensionSchema string) string {
	var trustedClusterSchema string
	if extensionSchema == "" {
		trustedClusterSchema = fmt.Sprintf(TrustedClusterSpecSchemaTemplate, RoleMapSchema, "")
	} else {
		trustedClusterSchema = fmt.Sprintf(TrustedClusterSpecSchemaTemplate, RoleMapSchema, ","+extensionSchema)
	}
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, trustedClusterSchema, DefaultDefinitions)
}

// UnmarshalTrustedCluster unmarshals the TrustedCluster resource from JSON.
func UnmarshalTrustedCluster(bytes []byte, opts ...MarshalOption) (TrustedCluster, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var trustedCluster TrustedClusterV2

	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing resource data")
	}

	if cfg.SkipValidation {
		if err := utils.FastUnmarshal(bytes, &trustedCluster); err != nil {
			return nil, trace.BadParameter(err.Error())
		}
	} else {
		err := utils.UnmarshalWithSchema(GetTrustedClusterSchema(""), &trustedCluster, bytes)
		if err != nil {
			return nil, trace.BadParameter(err.Error())
		}
	}

	if err = ValidateTrustedCluster(&trustedCluster); err != nil {
		return nil, trace.Wrap(err)
	}
	if cfg.ID != 0 {
		trustedCluster.SetResourceID(cfg.ID)
	}
	if !cfg.Expires.IsZero() {
		trustedCluster.SetExpiry(cfg.Expires)
	}
	return &trustedCluster, nil
}

// MarshalTrustedCluster marshals the TrustedCluster resource to JSON.
func MarshalTrustedCluster(c TrustedCluster, opts ...MarshalOption) ([]byte, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch resource := c.(type) {
	case *TrustedClusterV2:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *resource
			copy.SetResourceID(0)
			resource = &copy
		}
		return utils.FastMarshal(resource)
	default:
		return nil, trace.BadParameter("unrecognized resource version %T", c)
	}
}
