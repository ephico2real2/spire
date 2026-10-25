package delegatedidentity

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	agentctx "github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type expiryDelegateManager struct {
	manager.Manager
	grant, target *common.RegistrationEntry
	fetches       int
}

func (m *expiryDelegateManager) MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry {
	for _, selector := range selectors {
		if selector.Type == "test" && selector.Value == "delegate" {
			return []*common.RegistrationEntry{m.grant}
		}
	}
	return []*common.RegistrationEntry{m.target}
}

func (m *expiryDelegateManager) FetchJWTSVID(context.Context, *common.RegistrationEntry, []string) (*client.JWTSVID, error) {
	m.fetches++
	// A fixture credential result, not a claim of cryptographic JWT verification.
	return &client.JWTSVID{Token: "fixture-token", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestExpiredDelegateCannotStartNewTargetJWTRPC(t *testing.T) {
	log, _ := test.NewNullLogger()
	grant := &common.RegistrationEntry{
		EntryId: "delegate", SpiffeId: "spiffe://example.org/delegate",
		EntryExpiry: time.Now().Add(time.Hour).Unix(),
	}
	target := &common.RegistrationEntry{
		EntryId: "target", SpiffeId: "spiffe://example.org/workload",
		EntryExpiry: time.Now().Add(time.Hour).Unix(),
	}
	m := &expiryDelegateManager{grant: grant, target: target}
	service := New(Config{Manager: m, AuthorizedDelegates: []string{grant.SpiffeId}})
	service.peerAttestor = FakeAttestor{selectors: []*common.Selector{{Type: "test", Value: "delegate"}}}
	ctx := agentctx.WithLogger(context.Background(), log)
	req := &delegatedidentityv1.FetchJWTSVIDsRequest{
		Selectors: []*types.Selector{{Type: "test", Value: "target"}},
		Audience:  []string{"audience"},
	}
	response, err := service.FetchJWTSVIDs(ctx, req)
	require.NoError(t, err)
	require.Len(t, response.Svids, 1)
	require.Equal(t, 1, m.fetches)

	grant.EntryExpiry = time.Now().Add(-time.Hour).Unix()
	for range 3 {
		response, err = service.FetchJWTSVIDs(ctx, req)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.Nil(t, response)
		require.Equal(t, 1, m.fetches, "expired delegate reached fresh target retrieval")
	}
	require.True(t, target.EntryExpiry > time.Now().Unix())

	grant.EntryExpiry = time.Now().Add(time.Hour).Unix()
	response, err = service.FetchJWTSVIDs(ctx, req)
	require.NoError(t, err)
	require.Len(t, response.Svids, 1)
	require.Equal(t, 2, m.fetches)

	grant.EntryExpiry = 0
	_, err = service.FetchJWTSVIDs(ctx, req)
	require.NoError(t, err)
	require.Equal(t, 3, m.fetches)
}
