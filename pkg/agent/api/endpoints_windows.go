//go:build windows

package api

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/spire/pkg/common/sddl"
)

func (e *Endpoints) createListener() (net.Listener, error) {
	if e.c.DelegatedOnly {
		return nil, fmt.Errorf("the DelegatedIdentity-only listener is supported only on Linux")
	}
	l, err := e.listener.ListenPipe(e.c.BindAddr.String(), &winio.PipeConfig{SecurityDescriptor: sddl.PrivateListener})
	if err != nil {
		return nil, fmt.Errorf("error creating named pipe listener: %w", err)
	}
	return l, nil
}
