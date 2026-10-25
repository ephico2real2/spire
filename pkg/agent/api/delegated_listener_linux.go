//go:build linux

package api

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spiffe/spire/pkg/common/util"
)

const (
	// delegatedSocketMode lets the owner (agent) and the socket group connect.
	delegatedSocketMode = 0o660
	// delegatedDirMode grants the socket group search only; group members can
	// reach the socket but cannot list, create, rename or remove entries.
	// Everyone else cannot reach the socket at all.
	delegatedDirMode = os.ModeSetgid | 0o710
)

// createDelegatedListener binds the DelegatedIdentity-only Unix socket.
//
// The parent directory is provisioned outside the agent (for example by a
// root init container) as owner=agent UID, group=SocketGroup, mode 2710. The
// set-group-ID bit makes the bound socket inherit SocketGroup, so the agent
// needs neither membership of that group nor CAP_CHOWN/CAP_DAC_OVERRIDE. The
// agent never creates, chmods or chowns this directory and never touches the
// Workload or Admin socket directories. (A chmod by an owner that is not a
// member of the directory group would silently clear the set-group-ID bit.)
//
// No mode change of the directory is needed while binding: other users have
// no search permission on it, so between bind and the final chmod only the
// agent and the socket group, the intended clients, can reach the socket.
func (e *Endpoints) createDelegatedListener() (listener net.Listener, err error) {
	path := e.c.BindAddr.String()
	dir := filepath.Dir(path)
	group := e.c.SocketGroup
	if e.c.BindAddr.Network() != "unix" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 107 {
		return nil, fmt.Errorf("invalid DelegatedIdentity-only socket path %q", path)
	}
	if group <= 0 || group == os.Getegid() {
		return nil, fmt.Errorf("DelegatedIdentity-only socket group %d must be non-root and differ from the agent's own group", group)
	}
	if err := checkDelegatedParent(dir, group); err != nil {
		return nil, err
	}
	if err := removeStaleDelegatedSocket(path, group); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil && listener != nil {
			listener.Close()
			listener = nil
		}
	}()
	listener, err = e.listener.ListenUnix("unix", util.GetUnixAddr(path))
	if err != nil {
		return nil, fmt.Errorf("create DelegatedIdentity-only listener: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return listener, fmt.Errorf("inspect DelegatedIdentity-only socket: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(group) {
		return listener, fmt.Errorf("DelegatedIdentity-only socket did not inherit group %d from its set-group-ID parent", group)
	}
	if err = os.Chmod(path, delegatedSocketMode); err != nil {
		return listener, fmt.Errorf("set DelegatedIdentity-only socket mode: %w", err)
	}
	return listener, nil
}

// checkDelegatedParent requires an existing, non-symlink path whose last
// component is owned by the agent UID and the socket group with mode 2710.
func checkDelegatedParent(dir string, group int) error {
	for part := dir; ; part = filepath.Dir(part) {
		info, err := os.Lstat(part)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("DelegatedIdentity-only directory component %q is missing, not a directory or a symlink", part)
		}
		if part == string(filepath.Separator) {
			break
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	mode := info.Mode() & (os.ModePerm | os.ModeSetgid | os.ModeSetuid | os.ModeSticky)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(group) || mode != delegatedDirMode {
		return fmt.Errorf("DelegatedIdentity-only directory %q must be owned by the agent UID and group %d with mode 2710", dir, group)
	}
	return nil
}

// removeStaleDelegatedSocket removes only our own inactive socket. It refuses
// a foreign or non-socket inode and an active listener (another agent).
func removeStaleDelegatedSocket(path string, group int) error {
	previous, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := previous.Sys().(*syscall.Stat_t)
	if !ok || previous.Mode()&os.ModeSocket == 0 || st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(group) {
		return fmt.Errorf("refusing to replace foreign or non-socket path %q", path)
	}
	conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		conn.Close()
		return fmt.Errorf("a DelegatedIdentity-only listener is already active at %q", path)
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return fmt.Errorf("cannot establish that %q is stale: %w", path, dialErr)
	}
	return os.Remove(path)
}
