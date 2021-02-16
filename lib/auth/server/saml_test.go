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

package server

import (
	"context"
	"strings"
	"testing"
	"time"

	authority "github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/jonboulle/clockwork"
	"gopkg.in/check.v1"
)

type SAMLSuite struct {
	a *Server
	b backend.Backend
	c clockwork.FakeClock
}

var _ = check.Suite(&SAMLSuite{})

func (s *SAMLSuite) SetUpSuite(c *check.C) {
	utils.InitLoggerForTests(testing.Verbose())

	s.c = clockwork.NewFakeClockAt(time.Now())

	var err error
	s.b, err = lite.NewWithConfig(context.Background(), lite.Config{
		Path:             c.MkDir(),
		PollStreamPeriod: 200 * time.Millisecond,
		Clock:            s.c,
	})
	c.Assert(err, check.IsNil)

	clusterName, err := services.NewClusterName(services.ClusterNameSpecV2{
		ClusterName: "me.localhost",
	})
	c.Assert(err, check.IsNil)

	authConfig := &InitConfig{
		ClusterName:            clusterName,
		Backend:                s.b,
		Authority:              authority.New(),
		SkipPeriodicOperations: true,
	}
	s.a, err = NewServer(authConfig)
	c.Assert(err, check.IsNil)
}

func (s *SAMLSuite) TestCreateSAMLUser(c *check.C) {
	// Create SAML user with 1 minute expiry.
	_, err := s.a.createSAMLUser(&createUserParams{
		connectorName: "samlService",
		username:      "foo@example.com",
		logins:        []string{"foo"},
		roles:         []string{"admin"},
		sessionTTL:    1 * time.Minute,
	})
	c.Assert(err, check.IsNil)

	// Within that 1 minute period the user should still exist.
	_, err = s.a.GetUser("foo@example.com", false)
	c.Assert(err, check.IsNil)

	// Advance time 2 minutes, the user should be gone.
	s.c.Advance(2 * time.Minute)
	_, err = s.a.GetUser("foo@example.com", false)
	c.Assert(err, check.NotNil)
}

func (s *SAMLSuite) TestParseFromMetadata(c *check.C) {
	input := fixtures.SAMLOktaConnectorV2

	decoder := kyaml.NewYAMLOrJSONDecoder(strings.NewReader(input), defaults.LookaheadBufSize)
	var raw UnknownResource
	err := decoder.Decode(&raw)
	c.Assert(err, check.IsNil)

	oc, err := UnmarshalSAMLConnector(raw.Raw)
	c.Assert(err, check.IsNil)
	err = ValidateSAMLConnector(oc)
	c.Assert(err, check.IsNil)
	c.Assert(oc.GetIssuer(), check.Equals, "http://www.okta.com/exkafftca6RqPVgyZ0h7")
	c.Assert(oc.GetSSO(), check.Equals, "https://dev-813354.oktapreview.com/app/gravitationaldev813354_teleportsaml_1/exkafftca6RqPVgyZ0h7/sso/saml")
	c.Assert(oc.GetAssertionConsumerService(), check.Equals, "https://localhost:3080/v1/webapi/saml/acs")
	c.Assert(oc.GetAudience(), check.Equals, "https://localhost:3080/v1/webapi/saml/acs")
	c.Assert(oc.GetSigningKeyPair(), check.NotNil)
	c.Assert(oc.GetAttributes(), check.DeepEquals, []string{"groups"})
}
