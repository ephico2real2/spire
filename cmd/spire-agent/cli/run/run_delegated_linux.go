//go:build linux

package run

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/spiffe/spire/pkg/agent"
)

// configureDelegatedIdentity validates the opt-in DelegatedIdentity-only
// socket. It must live in its own directory, disjoint from the Workload API,
// Admin and Broker socket directories, so their ownership and modes stay
// untouched, and it requires authorized_delegates.
func configureDelegatedIdentity(c *agentConfig, ac *agent.Config) error {
	path, group := c.Experimental.DelegatedIdentitySocketPath, c.Experimental.DelegatedIdentitySocketGroup
	if path == "" && group == 0 {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 107 {
		return errors.New("experimental.delegated_identity_socket_path must be an absolute, clean Unix socket path of at most 107 bytes")
	}
	if group <= 0 {
		return errors.New("experimental.delegated_identity_socket_group must be a non-root group ID")
	}
	if len(ac.AuthorizedDelegates) == 0 {
		return errors.New("experimental.delegated_identity_socket_path requires authorized_delegates")
	}
	dir := filepath.Dir(path)
	others := append([]net.Addr{ac.AdminBindAddress, ac.BindAddress}, ac.Broker.BindAddresses...)
	for _, other := range others {
		if other == nil || other.Network() != "unix" {
			continue
		}
		otherDir := filepath.Dir(other.String())
		if nestedDir(dir, otherDir) || nestedDir(otherDir, dir) {
			return fmt.Errorf("experimental.delegated_identity_socket_path directory %q must be disjoint from the socket directory %q", dir, otherDir)
		}
	}
	ac.DelegatedIdentityBindAddress = &net.UnixAddr{Name: path, Net: "unix"}
	ac.DelegatedIdentitySocketGroup = group
	return nil
}

// nestedDir reports whether child equals or is inside parent.
func nestedDir(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}
