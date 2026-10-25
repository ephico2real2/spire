//go:build !linux

package run

import (
	"errors"

	"github.com/spiffe/spire/pkg/agent"
)

func configureDelegatedIdentity(c *agentConfig, _ *agent.Config) error {
	if c.Experimental.DelegatedIdentitySocketPath != "" || c.Experimental.DelegatedIdentitySocketGroup != 0 {
		return errors.New("experimental.delegated_identity_socket_path is supported only on Linux")
	}
	return nil
}
