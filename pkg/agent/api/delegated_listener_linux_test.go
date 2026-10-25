//go:build linux

package api

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/debug/v1"
	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/logger/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

// delegatedTestGroup is an arbitrary non-agent group. Root (the test runner
// in the pinned Linux builder) can provision a directory with it, exactly as
// the init container does on the node.
const delegatedTestGroup = 4242

const (
	testDelegate = "spiffe://example.org/ztunnel-proxy"
	testTarget   = "spiffe://example.org/ns/target/sa/app"
)

// TestMain runs the cross-process DAC helpers. A helper is this test binary
// re-executed with different credentials; it never runs the test suite.
func TestMain(m *testing.M) {
	switch os.Getenv(dacEnvRole) {
	case "":
		os.Exit(m.Run())
	case "agent":
		os.Exit(runDACAgent())
	case "client":
		os.Exit(runDACClient())
	default:
		fmt.Fprintln(os.Stderr, "unknown helper role")
		os.Exit(2)
	}
}

// recordingAttestor attests every caller as unix:uid:0 and records the PID
// that the peer tracker delivered.
type recordingAttestor struct{ pid atomic.Int64 }

func (a *recordingAttestor) Attest(_ context.Context, pid int) ([]*common.Selector, error) {
	a.pid.Store(int64(pid))
	return []*common.Selector{{Type: "unix", Value: "uid:0"}}, nil
}
func (*recordingAttestor) AttestReference(context.Context, *anypb.Any) ([]*common.Selector, error) {
	return nil, status.Error(codes.Unimplemented, "test")
}

// grantManager registers the caller (unix:uid:0) as the delegate according to
// grant, and a target workload (k8s:pod-uid:target).
type grantManager struct {
	manager.Manager
	grant   atomic.Int32 // 0 absent, 1 current, 2 expired
	fetches atomic.Int32
}

func (m *grantManager) MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry {
	for _, s := range selectors {
		switch {
		case s.Type == "unix" && s.Value == "uid:0":
			expiry := time.Now().Add(time.Hour).Unix()
			switch m.grant.Load() {
			case 0:
				return nil
			case 2:
				expiry = time.Now().Add(-time.Hour).Unix()
			}
			return []*common.RegistrationEntry{{SpiffeId: testDelegate, EntryExpiry: expiry}}
		case s.Type == "k8s" && s.Value == "pod-uid:target":
			return []*common.RegistrationEntry{{SpiffeId: testTarget}}
		}
	}
	return nil
}

func (m *grantManager) FetchJWTSVID(_ context.Context, entry *common.RegistrationEntry, _ []string) (*client.JWTSVID, error) {
	m.fetches.Add(1)
	// Routing fixture: shows the authorized request reached issuance. It is
	// not cryptographic issuance evidence.
	return &client.JWTSVID{Token: "routing-fixture:" + entry.SpiffeId, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatalf("delegated listener tests provision directory ownership and must run as root (euid %d)", os.Geteuid())
	}
}

// provisionDelegatedDir creates parent/delegated as the init container does:
// owner=agent (this process), group=gid, the given mode.
func provisionDelegatedDir(t *testing.T, mode os.FileMode, gid int) string {
	t.Helper()
	parent := t.TempDir()
	dir := filepath.Join(parent, "delegated")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.Chown(dir, os.Geteuid(), gid))
	require.NoError(t, os.Chmod(dir, mode))
	return dir
}

func testConfig(path string, delegatedOnly bool, group int, mgr manager.Manager, att *recordingAttestor) *Config {
	log, _ := test.NewNullLogger()
	return &Config{
		BindAddr:            &net.UnixAddr{Net: "unix", Name: path},
		DelegatedOnly:       delegatedOnly,
		SocketGroup:         group,
		Listening:           make(chan struct{}),
		Manager:             mgr,
		Log:                 log,
		RootLog:             log,
		Metrics:             telemetry.Blackhole{},
		Attestor:            att,
		AuthorizedDelegates: []string{testDelegate},
		Uptime:              func() time.Duration { return time.Second },
	}
}

func newTestEndpoints(path string, delegatedOnly bool, group int) *Endpoints {
	return New(testConfig(path, delegatedOnly, group, &grantManager{}, &recordingAttestor{}))
}

func serve(t *testing.T, e *Endpoints) (*grpc.ClientConn, context.CancelFunc, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.ListenAndServe(ctx) }()
	select {
	case <-e.c.Listening:
	case err := <-done:
		cancel()
		t.Fatalf("listener did not start: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("listener start timed out")
	}
	conn, err := grpc.NewClient("unix://"+e.c.BindAddr.String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn, cancel, done
}

func requireCode(t *testing.T, err error, want codes.Code, msg string) {
	t.Helper()
	require.Error(t, err, msg)
	require.Equal(t, want, status.Code(err), "%s: %v", msg, err)
}

func dirMode(t *testing.T, dir string) (os.FileMode, *syscall.Stat_t) {
	t.Helper()
	info, err := os.Lstat(dir)
	require.NoError(t, err)
	return info.Mode() & (os.ModePerm | os.ModeSetgid | os.ModeSetuid | os.ModeSticky), info.Sys().(*syscall.Stat_t)
}

func TestDelegatedOnlyListenerServesOnlyDelegatedIdentity(t *testing.T) {
	requireRoot(t)
	dir := provisionDelegatedDir(t, delegatedDirMode, delegatedTestGroup)
	path := filepath.Join(dir, "delegated.sock")
	mgr, att := &grantManager{}, &recordingAttestor{}
	mgr.grant.Store(1)
	conn, cancel, done := serve(t, New(testConfig(path, true, delegatedTestGroup, mgr, att)))
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()

	// Debug and Logger are not registered on the delegated-only socket.
	_, err := debugv1.NewDebugClient(conn).GetInfo(ctx, &debugv1.GetInfoRequest{})
	requireCode(t, err, codes.Unimplemented, "Debug must not be served")
	_, err = loggerv1.NewLoggerClient(conn).GetLogger(ctx, &loggerv1.GetLoggerRequest{})
	requireCode(t, err, codes.Unimplemented, "Logger must not be served")
	_, err = loggerv1.NewLoggerClient(conn).SetLogLevel(ctx, &loggerv1.SetLogLevelRequest{})
	requireCode(t, err, codes.Unimplemented, "Logger set must not be served")
	_, err = loggerv1.NewLoggerClient(conn).ResetLogLevel(ctx, &loggerv1.ResetLogLevelRequest{})
	requireCode(t, err, codes.Unimplemented, "Logger reset must not be served")

	// DelegatedIdentity is served; the caller PID reached the attestor through
	// the real peer tracker.
	resp, err := delegatedidentityv1.NewDelegatedIdentityClient(conn).FetchJWTSVIDs(ctx, &delegatedidentityv1.FetchJWTSVIDsRequest{Audience: []string{"a"}, Selectors: []*types.Selector{{Type: "k8s", Value: "pod-uid:target"}}})
	require.NoError(t, err)
	require.Len(t, resp.Svids, 1)
	require.Equal(t, int64(os.Getpid()), att.pid.Load())

	// Exact ownership and modes.
	info, err := os.Lstat(path)
	require.NoError(t, err)
	st := info.Sys().(*syscall.Stat_t)
	require.NotZero(t, info.Mode()&os.ModeSocket)
	require.Equal(t, os.FileMode(0o660), info.Mode().Perm())
	require.Equal(t, uint32(os.Geteuid()), st.Uid)
	require.Equal(t, uint32(delegatedTestGroup), st.Gid, "socket inherits the set-group-ID parent group")
	mode, _ := dirMode(t, dir)
	require.Equal(t, delegatedDirMode, mode)

	cancel()
	require.NoError(t, <-done)
	_, err = os.Lstat(path)
	require.ErrorIs(t, err, os.ErrNotExist, "orderly stop removes the socket")
}

func TestDelegatedOnlyListenerAuthorizationAndRestart(t *testing.T) {
	requireRoot(t)
	dir := provisionDelegatedDir(t, delegatedDirMode, delegatedTestGroup)
	path := filepath.Join(dir, "delegated.sock")
	mgr := &grantManager{}
	req := &delegatedidentityv1.FetchJWTSVIDsRequest{Audience: []string{"a"}, Selectors: []*types.Selector{{Type: "k8s", Value: "pod-uid:target"}}}
	for round, allowlist := range [][]string{{testDelegate}, nil, {testDelegate}} {
		cfg := testConfig(path, true, delegatedTestGroup, mgr, &recordingAttestor{})
		cfg.AuthorizedDelegates = allowlist
		conn, cancel, done := serve(t, New(cfg))
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		rpc := delegatedidentityv1.NewDelegatedIdentityClient(conn)
		before := mgr.fetches.Load()

		mgr.grant.Store(0)
		_, err := rpc.FetchJWTSVIDs(ctx, req)
		requireCode(t, err, codes.PermissionDenied, "no delegate registration")
		mgr.grant.Store(2)
		_, err = rpc.FetchJWTSVIDs(ctx, req)
		requireCode(t, err, codes.PermissionDenied, "expired delegate registration")
		require.Equal(t, before, mgr.fetches.Load(), "a denied caller never reaches issuance")

		mgr.grant.Store(1)
		resp, err := rpc.FetchJWTSVIDs(ctx, req)
		if allowlist == nil {
			requireCode(t, err, codes.PermissionDenied, "nil allowlist denies a registered caller")
			require.Equal(t, before, mgr.fetches.Load())
		} else {
			require.NoError(t, err, "round %d: restored delegate is served", round)
			require.Len(t, resp.Svids, 1)
			require.Equal(t, before+1, mgr.fetches.Load())
		}
		stop()
		cancel()
		require.NoError(t, <-done)
		_, err = os.Lstat(path)
		require.ErrorIs(t, err, os.ErrNotExist, "round %d: only the owned socket is removed on shutdown", round)
		mode, st := dirMode(t, dir)
		require.Equal(t, delegatedDirMode, mode, "the agent never changes its directory")
		require.Equal(t, uint32(delegatedTestGroup), st.Gid)
	}
}

func TestOriginalAdminListenerStillServesAllServices(t *testing.T) {
	requireRoot(t)
	path := filepath.Join(t.TempDir(), "admin.sock")
	conn, cancel, done := serve(t, newTestEndpoints(path, false, 0))
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_, err := loggerv1.NewLoggerClient(conn).GetLogger(ctx, &loggerv1.GetLoggerRequest{})
	require.NoError(t, err, "the original Admin socket keeps Logger")
	info, err := os.Lstat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o770), info.Mode().Perm(), "original Admin socket mode is unchanged")
	cancel()
	require.NoError(t, <-done)
}

func TestDelegatedOnlyListenerRejectsUnsafeParentsAndGroups(t *testing.T) {
	requireRoot(t)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) (string, int)
	}{
		{"no set-group-ID bit", func(t *testing.T) (string, int) {
			return provisionDelegatedDir(t, 0o710, delegatedTestGroup), delegatedTestGroup
		}},
		{"closed to the group", func(t *testing.T) (string, int) {
			return provisionDelegatedDir(t, os.ModeSetgid|0o700, delegatedTestGroup), delegatedTestGroup
		}},
		{"group can list", func(t *testing.T) (string, int) {
			return provisionDelegatedDir(t, os.ModeSetgid|0o750, delegatedTestGroup), delegatedTestGroup
		}},
		{"world access", func(t *testing.T) (string, int) {
			return provisionDelegatedDir(t, os.ModeSetgid|0o711, delegatedTestGroup), delegatedTestGroup
		}},
		{"wrong group", func(t *testing.T) (string, int) {
			return provisionDelegatedDir(t, delegatedDirMode, delegatedTestGroup+1), delegatedTestGroup
		}},
		{"foreign owner", func(t *testing.T) (string, int) {
			dir := provisionDelegatedDir(t, delegatedDirMode, delegatedTestGroup)
			require.NoError(t, os.Chown(dir, 1234, delegatedTestGroup))
			require.NoError(t, os.Chmod(dir, delegatedDirMode))
			return dir, delegatedTestGroup
		}},
		{"missing directory", func(t *testing.T) (string, int) {
			return filepath.Join(t.TempDir(), "absent"), delegatedTestGroup
		}},
		{"symlinked directory", func(t *testing.T) (string, int) {
			dir := provisionDelegatedDir(t, delegatedDirMode, delegatedTestGroup)
			link := filepath.Join(t.TempDir(), "link")
			require.NoError(t, os.Symlink(dir, link))
			return link, delegatedTestGroup
		}},
		{"root group", func(t *testing.T) (string, int) {
			return provisionDelegatedDir(t, delegatedDirMode, 0), 0
		}},
		{"agent's own group", func(t *testing.T) (string, int) {
			return provisionDelegatedDir(t, delegatedDirMode, os.Getegid()), os.Getegid()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, group := tc.setup(t)
			var beforeMode os.FileMode
			if info, err := os.Lstat(dir); err == nil {
				beforeMode = info.Mode()
			}
			listener, err := newTestEndpoints(filepath.Join(dir, "delegated.sock"), true, group).createListener()
			require.Error(t, err)
			require.Nil(t, listener)
			_, statErr := os.Lstat(filepath.Join(dir, "delegated.sock"))
			require.True(t, os.IsNotExist(statErr), "no socket left behind: %v", statErr)
			if info, err := os.Lstat(dir); err == nil {
				require.Equal(t, beforeMode, info.Mode(), "a refused directory is not modified")
			}
		})
	}
}

func TestDelegatedOnlyListenerStaleActiveAndForeignSockets(t *testing.T) {
	requireRoot(t)
	dir := provisionDelegatedDir(t, delegatedDirMode, delegatedTestGroup)
	path := filepath.Join(dir, "delegated.sock")

	// A stale socket left by a crashed agent is replaced.
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	require.NoError(t, err)
	stale.SetUnlinkOnClose(false)
	require.NoError(t, stale.Close())
	conn, cancel, done := serve(t, newTestEndpoints(path, true, delegatedTestGroup))
	require.NotNil(t, conn)

	// A second agent cannot unlink the active listener.
	before, err := os.Lstat(path)
	require.NoError(t, err)
	second, err := newTestEndpoints(path, true, delegatedTestGroup).createListener()
	require.ErrorContains(t, err, "already active")
	require.Nil(t, second)
	after, err := os.Lstat(path)
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after), "the active socket inode is untouched")
	cancel()
	require.NoError(t, <-done)

	// A regular file, a symlink or a socket of another group is never replaced.
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	_, err = newTestEndpoints(path, true, delegatedTestGroup).createListener()
	require.ErrorContains(t, err, "refusing to replace")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "x", string(data))
	require.NoError(t, os.Remove(path))

	require.NoError(t, os.Symlink(filepath.Join(dir, "foreign"), path))
	_, err = newTestEndpoints(path, true, delegatedTestGroup).createListener()
	require.ErrorContains(t, err, "refusing to replace")
	target, err := os.Readlink(path)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "foreign"), target)
	require.NoError(t, os.Remove(path))

	foreign, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	require.NoError(t, err)
	foreign.SetUnlinkOnClose(false)
	require.NoError(t, foreign.Close())
	require.NoError(t, os.Chown(path, -1, delegatedTestGroup+1))
	_, err = newTestEndpoints(path, true, delegatedTestGroup).createListener()
	require.ErrorContains(t, err, "refusing to replace")
	_, err = os.Lstat(path)
	require.NoError(t, err, "a socket of another group is preserved")
}

// Exact service registration for both listener modes, by generated service
// descriptor. The Debug/Logger clients used in the negative tests call methods
// of these same descriptors, so their Unimplemented results are not vacuous.
func TestListenerModesRegisterExactServices(t *testing.T) {
	names := func(delegatedOnly bool) []string {
		server := grpc.NewServer()
		defer server.Stop()
		newTestEndpoints("/unused", delegatedOnly, delegatedTestGroup).registerServices(server)
		var out []string
		for name := range server.GetServiceInfo() {
			out = append(out, name)
		}
		return out
	}
	debugService := debugv1.Debug_ServiceDesc.ServiceName
	delegatedService := delegatedidentityv1.DelegatedIdentity_ServiceDesc.ServiceName
	loggerService := loggerv1.Logger_ServiceDesc.ServiceName
	require.ElementsMatch(t, []string{delegatedService}, names(true))
	require.ElementsMatch(t, []string{debugService, delegatedService, loggerService}, names(false))
	require.Equal(t, "/"+debugService+"/GetInfo", debugv1.Debug_GetInfo_FullMethodName)
	require.Equal(t, "/"+loggerService+"/SetLogLevel", loggerv1.Logger_SetLogLevel_FullMethodName)
}

// ---------------------------------------------------------------------------
// Cross-process DAC test. A root test proves nothing about DAC: here the agent
// runs as UID/GID 1000 with no capabilities and no membership of the socket
// group, and every client runs with its own credentials and no capabilities.
// ---------------------------------------------------------------------------

const (
	dacEnvRole  = "CMTC_DELEGATED_DAC_ROLE"
	dacEnvPath  = "CMTC_DELEGATED_DAC_PATH"
	dacEnvGroup = "CMTC_DELEGATED_DAC_GROUP"
	dacEnvDrop  = "CMTC_DELEGATED_DAC_DROP_CAPS"

	dacAgentUID = 1000
	dacAgentGID = 1000
)

// procAttestor attests a caller by the real and group IDs in /proc, the same
// basis as the unix workload attestor.
type procAttestor struct{}

func (procAttestor) Attest(_ context.Context, pid int) ([]*common.Selector, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	var selectors []*common.Selector
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && (fields[0] == "Uid:" || fields[0] == "Gid:") {
			selectors = append(selectors, &common.Selector{Type: "unix", Value: strings.ToLower(strings.TrimSuffix(fields[0], ":")) + ":" + fields[1]})
		}
	}
	return selectors, nil
}
func (procAttestor) AttestReference(context.Context, *anypb.Any) ([]*common.Selector, error) {
	return nil, status.Error(codes.Unimplemented, "test")
}

// subsetManager returns entries whose selectors are all present.
type subsetManager struct {
	manager.Manager
	entries []*common.RegistrationEntry
}

func (m subsetManager) MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry {
	have := map[string]bool{}
	for _, s := range selectors {
		have[s.Type+":"+s.Value] = true
	}
	var out []*common.RegistrationEntry
	for _, entry := range m.entries {
		matched := len(entry.Selectors) > 0
		for _, s := range entry.Selectors {
			matched = matched && have[s.Type+":"+s.Value]
		}
		if matched {
			out = append(out, entry)
		}
	}
	return out
}

func (subsetManager) FetchJWTSVID(_ context.Context, entry *common.RegistrationEntry, _ []string) (*client.JWTSVID, error) {
	// Routing fixture, not cryptographic issuance evidence.
	return &client.JWTSVID{Token: "routing-fixture:" + entry.SpiffeId, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func capsAreZero() (bool, string) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, err.Error()
	}
	var caps []string
	zero := true
	for _, line := range strings.Split(string(data), "\n") {
		for _, key := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapAmb:"} {
			if strings.HasPrefix(line, key) {
				value := strings.TrimSpace(strings.TrimPrefix(line, key))
				caps = append(caps, key+value)
				zero = zero && strings.Trim(value, "0") == ""
			}
		}
	}
	return zero && len(caps) == 4, strings.Join(caps, ",")
}

func runDACAgent() int {
	if zero, caps := capsAreZero(); !zero {
		fmt.Printf("DAC-ERROR agent has capabilities %s\n", caps)
		return 2
	}
	group, err := strconv.Atoi(os.Getenv(dacEnvGroup))
	if err != nil {
		fmt.Printf("DAC-ERROR group: %v\n", err)
		return 2
	}
	groups, _ := os.Getgroups()
	fmt.Printf("DAC-AGENT uid=%d gid=%d groups=%v\n", os.Geteuid(), os.Getegid(), groups)
	log := logrus.New()
	log.SetOutput(os.Stderr)
	log.SetLevel(logrus.DebugLevel)
	listening := make(chan struct{})
	e := New(&Config{
		BindAddr:      &net.UnixAddr{Net: "unix", Name: os.Getenv(dacEnvPath)},
		DelegatedOnly: true,
		SocketGroup:   group,
		Listening:     listening,
		Manager: subsetManager{entries: []*common.RegistrationEntry{
			{SpiffeId: testDelegate, EntryExpiry: time.Now().Add(time.Hour).Unix(), Selectors: []*common.Selector{{Type: "unix", Value: "uid:0"}, {Type: "unix", Value: "gid:" + strconv.Itoa(group)}}},
			{SpiffeId: "spiffe://example.org/agent-uid-process", Selectors: []*common.Selector{{Type: "unix", Value: "uid:" + strconv.Itoa(dacAgentUID)}}},
			{SpiffeId: testTarget, Selectors: []*common.Selector{{Type: "k8s", Value: "pod-uid:target"}}},
		}},
		Log:                 log,
		RootLog:             log,
		Metrics:             telemetry.Blackhole{},
		Attestor:            procAttestor{},
		AuthorizedDelegates: []string{testDelegate},
		Uptime:              func() time.Duration { return time.Second },
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.ListenAndServe(ctx) }()
	select {
	case <-listening:
		fmt.Println("DAC-READY")
	case err := <-done:
		fmt.Printf("DAC-LISTEN-ERROR %v\n", err)
		return 3
	case <-time.After(10 * time.Second):
		fmt.Println("DAC-LISTEN-ERROR timeout")
		return 3
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	cancel()
	fmt.Printf("DAC-STOPPED err=%v\n", <-done)
	return 0
}

// dropAllCapsAndReexec clears the bounding, ambient and thread capability sets
// of a UID 0 helper and re-executes it from the same OS thread, so the new
// image starts as UID 0 with no capabilities (as a container with
// capabilities.drop: [ALL]).
func dropAllCapsAndReexec() error {
	runtime.LockOSThread()
	last, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(last)))
	if err != nil {
		return err
	}
	for c := 0; c <= n; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
			return fmt.Errorf("drop bounding capability %d: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var data [2]unix.CapUserData
	if err := unix.Capset(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &data[0]); err != nil {
		return err
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, dacEnvDrop+"=") {
			env = append(env, kv)
		}
	}
	return syscall.Exec(exe, os.Args, append(env, dacEnvDrop+"=done"))
}

func runDACClient() int {
	if os.Getenv(dacEnvDrop) == "1" {
		err := dropAllCapsAndReexec()
		fmt.Printf("DAC-ERROR drop capabilities: %v\n", err)
		return 2
	}
	zero, caps := capsAreZero()
	if !zero {
		fmt.Printf("DAC-ERROR client has capabilities %s\n", caps)
		return 2
	}
	path := os.Getenv(dacEnvPath)
	result := []string{fmt.Sprintf("uid=%d", os.Geteuid()), fmt.Sprintf("gid=%d", os.Getegid()), "caps=0"}
	errno := func(err error) string {
		var e syscall.Errno
		switch {
		case err == nil:
			return "ok"
		case errors.As(err, &e):
			return unix.ErrnoName(e)
		default:
			return "error:" + strings.ReplaceAll(err.Error(), " ", "_")
		}
	}
	_, err := os.ReadDir(filepath.Dir(path))
	result = append(result, "list="+errno(err))
	raw, err := net.Dial("unix", path)
	result = append(result, "dial="+errno(err))
	if err == nil {
		raw.Close()
		conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Printf("DAC-ERROR grpc client: %v\n", err)
			return 2
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := delegatedidentityv1.NewDelegatedIdentityClient(conn).FetchJWTSVIDs(ctx, &delegatedidentityv1.FetchJWTSVIDsRequest{Audience: []string{"dac"}, Selectors: []*types.Selector{{Type: "k8s", Value: "pod-uid:target"}}})
		result = append(result, "jwt="+status.Code(err).String())
		if err == nil {
			result = append(result, fmt.Sprintf("svids=%d", len(resp.Svids)), "token="+resp.Svids[0].Token)
		}
		_, err = debugv1.NewDebugClient(conn).GetInfo(ctx, &debugv1.GetInfoRequest{})
		result = append(result, "debug="+status.Code(err).String())
		_, err = loggerv1.NewLoggerClient(conn).GetLogger(ctx, &loggerv1.GetLoggerRequest{})
		result = append(result, "getlogger="+status.Code(err).String())
		_, err = loggerv1.NewLoggerClient(conn).SetLogLevel(ctx, &loggerv1.SetLogLevelRequest{})
		result = append(result, "setlevel="+status.Code(err).String())
		_, err = loggerv1.NewLoggerClient(conn).ResetLogLevel(ctx, &loggerv1.ResetLogLevelRequest{})
		result = append(result, "resetlevel="+status.Code(err).String())
	}
	fmt.Println("DAC-RESULT " + strings.Join(result, " "))
	return 0
}

type dacHarness struct {
	t    *testing.T
	exe  string
	dir  string
	path string
}

// newDACHarness lays out base/ (0711), a copy of this test binary that the
// helpers can execute, base/run/ (0755) and base/run/delegated provisioned as
// agent 1000:group with mode, as the root init container does on a node.
func newDACHarness(t *testing.T, mode os.FileMode, group int) *dacHarness {
	t.Helper()
	requireRoot(t)
	base := t.TempDir()
	for _, d := range []string{filepath.Dir(base), base} {
		require.NoError(t, os.Chmod(d, 0o711))
	}
	self, err := os.Executable()
	require.NoError(t, err)
	exe := filepath.Join(base, "api.test")
	src, err := os.Open(self)
	require.NoError(t, err)
	defer src.Close()
	dst, err := os.OpenFile(exe, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	require.NoError(t, err)
	_, err = io.Copy(dst, src)
	require.NoError(t, err)
	require.NoError(t, dst.Close())
	run := filepath.Join(base, "run")
	require.NoError(t, os.Mkdir(run, 0o755))
	dir := filepath.Join(run, "delegated")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.Chown(dir, dacAgentUID, group))
	require.NoError(t, os.Chmod(dir, mode))
	return &dacHarness{t: t, exe: exe, dir: dir, path: filepath.Join(dir, "delegated.sock")}
}

func (h *dacHarness) command(role string, cred *syscall.Credential, env ...string) *exec.Cmd {
	cmd := exec.Command(h.exe, "-test.run=^$")
	cmd.Dir = "/"
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", dacEnvRole + "=" + role, dacEnvPath + "=" + h.path}, env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	return cmd
}

// syncBuffer collects helper stderr; exec writes it from its own goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type dacAgent struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan string
	stderr *syncBuffer
}

func (h *dacHarness) startAgent(group int) (*dacAgent, string) {
	h.t.Helper()
	cmd := h.command("agent", &syscall.Credential{Uid: dacAgentUID, Gid: dacAgentGID, Groups: []uint32{}}, dacEnvGroup+"="+strconv.Itoa(group))
	stdin, err := cmd.StdinPipe()
	require.NoError(h.t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(h.t, err)
	a := &dacAgent{cmd: cmd, stdin: stdin, lines: make(chan string, 16), stderr: &syncBuffer{}}
	cmd.Stderr = a.stderr
	require.NoError(h.t, cmd.Start())
	h.t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			a.lines <- scanner.Text()
		}
		close(a.lines)
	}()
	for {
		select {
		case line, ok := <-a.lines:
			if !ok {
				h.t.Fatalf("agent helper exited before reporting; stderr:\n%s", a.stderr.String())
			}
			if strings.HasPrefix(line, "DAC-READY") || strings.HasPrefix(line, "DAC-LISTEN-ERROR") || strings.HasPrefix(line, "DAC-ERROR") {
				return a, line
			}
			h.t.Log(line)
		case <-time.After(30 * time.Second):
			h.t.Fatalf("agent helper did not report; stderr:\n%s", a.stderr.String())
		}
	}
}

func (a *dacAgent) stop(t *testing.T) string {
	t.Helper()
	require.NoError(t, a.stdin.Close())
	var last string
	for line := range a.lines {
		last = line
	}
	require.NoError(t, a.cmd.Wait(), "agent stderr:\n%s", a.stderr.String())
	return last
}

func (h *dacHarness) client(uid, gid uint32, dropCaps bool) map[string]string {
	h.t.Helper()
	env := []string{}
	if dropCaps {
		env = append(env, dacEnvDrop+"=1")
	}
	cmd := h.command("client", &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}, env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(h.t, err, "client %d:%d stdout:\n%s\nstderr:\n%s", uid, gid, out, stderr.String())
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, "DAC-RESULT "); ok {
			h.t.Logf("client %d:%d %s", uid, gid, rest)
			result := map[string]string{}
			for _, kv := range strings.Fields(rest) {
				k, v, _ := strings.Cut(kv, "=")
				result[k] = v
			}
			return result
		}
	}
	h.t.Fatalf("client %d:%d produced no result:\n%s\nstderr:\n%s", uid, gid, out, stderr.String())
	return nil
}

func TestDelegatedOnlyListenerUnprivilegedDAC(t *testing.T) {
	h := newDACHarness(t, delegatedDirMode, delegatedTestGroup)
	agent, line := h.startAgent(delegatedTestGroup)
	require.Equal(t, "DAC-READY", line, "an agent with UID/GID 1000, no capabilities and no membership of the socket group must start; stderr:\n%s", agent.stderr.String())

	// The socket is 1000:group 0660 and the directory keeps 2710 1000:group:
	// the agent changed neither the directory mode nor its set-group-ID bit.
	info, err := os.Lstat(h.path)
	require.NoError(t, err)
	st := info.Sys().(*syscall.Stat_t)
	require.NotZero(t, info.Mode()&os.ModeSocket)
	require.Equal(t, os.FileMode(0o660), info.Mode().Perm())
	require.Equal(t, uint32(dacAgentUID), st.Uid)
	require.Equal(t, uint32(delegatedTestGroup), st.Gid)
	mode, dst := dirMode(t, h.dir)
	require.Equal(t, delegatedDirMode, mode)
	require.Equal(t, uint32(dacAgentUID), dst.Uid)
	require.Equal(t, uint32(delegatedTestGroup), dst.Gid)

	unimplemented := codes.Unimplemented.String()
	// The proxy: UID 0, the socket group, no capabilities. It can reach the
	// socket but not list the directory, gets the delegated credential and
	// cannot reach Debug or Logger.
	proxy := h.client(0, delegatedTestGroup, true)
	require.Equal(t, "EACCES", proxy["list"])
	require.Equal(t, "ok", proxy["dial"])
	require.Equal(t, codes.OK.String(), proxy["jwt"])
	require.Equal(t, "1", proxy["svids"])
	require.Equal(t, "routing-fixture:"+testTarget, proxy["token"])
	for _, rpc := range []string{"debug", "getlogger", "setlevel", "resetlevel"} {
		require.Equal(t, unimplemented, proxy[rpc], rpc)
	}

	// UID 0 without the socket group and without capabilities: no access.
	require.Equal(t, "EACCES", h.client(0, dacAgentGID, true)["dial"])
	// An unprivileged user: no access.
	require.Equal(t, "EACCES", h.client(65532, dacAgentGID, false)["dial"])

	// DAC admits these callers; authorization rejects them before issuance.
	sameUID := h.client(dacAgentUID, dacAgentGID, false)
	require.Equal(t, "ok", sameUID["dial"])
	require.Equal(t, codes.PermissionDenied.String(), sameUID["jwt"])
	groupMember := h.client(2000, delegatedTestGroup, false)
	require.Equal(t, "ok", groupMember["dial"])
	require.Equal(t, codes.PermissionDenied.String(), groupMember["jwt"])
	require.Equal(t, unimplemented, groupMember["setlevel"])

	require.Equal(t, "DAC-STOPPED err=<nil>", agent.stop(t))
	_, err = os.Lstat(h.path)
	require.ErrorIs(t, err, os.ErrNotExist, "orderly stop removes the socket")
	mode, _ = dirMode(t, h.dir)
	require.Equal(t, delegatedDirMode, mode)

	// Restart recovery as the same unprivileged agent.
	agent, line = h.startAgent(delegatedTestGroup)
	require.Equal(t, "DAC-READY", line, agent.stderr.String())
	require.Equal(t, codes.OK.String(), h.client(0, delegatedTestGroup, true)["jwt"])
	require.Equal(t, "DAC-STOPPED err=<nil>", agent.stop(t))
}

func TestDelegatedOnlyListenerUnprivilegedRefusesUnprovisionedDirectory(t *testing.T) {
	// Without the set-group-ID bit the unprivileged agent cannot give the
	// socket the proxy group. It must refuse and leave the directory as is.
	h := newDACHarness(t, 0o710, delegatedTestGroup)
	agent, line := h.startAgent(delegatedTestGroup)
	require.True(t, strings.HasPrefix(line, "DAC-LISTEN-ERROR"), line)
	for range agent.lines {
	}
	require.Error(t, agent.cmd.Wait())
	require.Contains(t, agent.stderr.String(), "Unable to create listener")
	_, err := os.Lstat(h.path)
	require.ErrorIs(t, err, os.ErrNotExist)
	mode, st := dirMode(t, h.dir)
	require.Equal(t, os.FileMode(0o710), mode)
	require.Equal(t, uint32(dacAgentUID), st.Uid)
	require.Equal(t, uint32(delegatedTestGroup), st.Gid)
}
