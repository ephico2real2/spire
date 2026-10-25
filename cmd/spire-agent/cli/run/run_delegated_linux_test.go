//go:build linux

package run

import (
	"net"
	"testing"

	"github.com/spiffe/spire/pkg/agent"
	"github.com/stretchr/testify/require"
)

func delegatedConfig(path string, group int) (*agentConfig, *agent.Config) {
	c := &agentConfig{}
	c.Experimental.DelegatedIdentitySocketPath = path
	c.Experimental.DelegatedIdentitySocketGroup = group
	ac := &agent.Config{
		BindAddress:         &net.UnixAddr{Net: "unix", Name: "/run/spire/sockets/agent/agent.sock"},
		AdminBindAddress:    &net.UnixAddr{Net: "unix", Name: "/run/spire/sockets/admin/admin.sock"},
		AuthorizedDelegates: []string{"spiffe://cmtc-a.mesh.example/ztunnel-proxy"},
	}
	return c, ac
}

func TestDelegatedIdentitySocketConfig(t *testing.T) {
	c, ac := delegatedConfig("", 0)
	require.NoError(t, configureDelegatedIdentity(c, ac))
	require.Nil(t, ac.DelegatedIdentityBindAddress, "disabled by default")

	c, ac = delegatedConfig("/run/spire/sockets/delegated/delegated.sock", 1337)
	require.NoError(t, configureDelegatedIdentity(c, ac))
	require.Equal(t, "/run/spire/sockets/delegated/delegated.sock", ac.DelegatedIdentityBindAddress.String())
	require.Equal(t, "unix", ac.DelegatedIdentityBindAddress.Network())
	require.Equal(t, 1337, ac.DelegatedIdentitySocketGroup)
	require.Equal(t, "/run/spire/sockets/admin/admin.sock", ac.AdminBindAddress.String(), "Admin socket untouched")

	for _, tc := range []struct {
		name, path string
		group      int
		delegates  []string
		want       string
	}{
		{"relative path", "run/delegated.sock", 1337, nil, "absolute, clean"},
		{"unclean path", "/run/spire/sockets/delegated/../delegated/delegated.sock", 1337, nil, "absolute, clean"},
		{"path too long", "/" + string(make([]byte, 120)), 1337, nil, "absolute, clean"},
		{"root group", "/run/spire/sockets/delegated/delegated.sock", 0, nil, "non-root group"},
		{"negative group", "/run/spire/sockets/delegated/delegated.sock", -1, nil, "non-root group"},
		{"group without path", "", 1337, nil, "absolute, clean"},
		{"no authorized delegates", "/run/spire/sockets/delegated/delegated.sock", 1337, []string{}, "requires authorized_delegates"},
		{"inside the Admin directory", "/run/spire/sockets/admin/delegated.sock", 1337, nil, "disjoint"},
		{"inside the Workload API directory", "/run/spire/sockets/agent/delegated.sock", 1337, nil, "disjoint"},
		{"parent of the Admin directory", "/run/spire/sockets/admin.sock", 1337, nil, ""},
		{"nested under the Admin directory", "/run/spire/sockets/admin/sub/delegated.sock", 1337, nil, "disjoint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ac := delegatedConfig(tc.path, tc.group)
			if tc.delegates != nil {
				ac.AuthorizedDelegates = tc.delegates
			}
			err := configureDelegatedIdentity(c, ac)
			if tc.want == "" {
				// /run/spire/sockets is the parent of both API directories,
				// so a socket placed directly in it is rejected as nested.
				require.ErrorContains(t, err, "disjoint")
				return
			}
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, ac.DelegatedIdentityBindAddress)
		})
	}
}
