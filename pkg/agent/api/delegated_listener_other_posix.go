//go:build !linux && !windows

package api

import (
	"fmt"
	"net"
)

func (e *Endpoints) createDelegatedListener() (net.Listener, error) {
	return nil, fmt.Errorf("the DelegatedIdentity-only listener is supported only on Linux")
}
