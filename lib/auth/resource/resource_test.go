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
	"testing"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

// TestOptions tests command options operations
func TestOptions(t *testing.T) {
	// test empty scenario
	out := AddOptions(nil)
	require.Empty(t, out)

	// make sure original option list is not affected
	in := []auth.MarshalOption{}
	out = AddOptions(in, WithResourceID(1))
	require.Empty(t, cmp.Diff(out, []auth.MarshalOption{}))
	require.Len(t, out, 1)

	cfg, err := CollectOptions(out)
	require.NoError(t, err)
	require.Equals(t, cfg.ID, int64(1))

	// Add a couple of other parameters
	out = AddOptions(in, WithResourceID(2), SkipValidation(), WithVersion(types.V2))
	require.Len(t, out, 3)
	cfg, err = CollectOptions(out)
	require.NoError(t, err)
	require.Equals(t, cfg.ID, int64(2))
	require.IsTrue(t, cfg.SkipValidation)
	require.Equals(t, cfg.Version, types.V2)
}
