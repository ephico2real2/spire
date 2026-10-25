package entrycache

import (
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

func TestFullCacheExpiredRegistrationDoesNotAuthorizeDescendants(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	future := time.Now().Add(time.Hour).Unix()
	td := spiffeid.RequireTrustDomainFromString("example.org")
	agent := spiffeid.RequireFromPath(td, "/spire/agent/node")
	aliasPath := "/alias/node"
	id := func(path string) *types.SPIFFEID {
		return &types.SPIFFEID{TrustDomain: td.String(), Path: path}
	}
	expiredAlias := &types.Entry{Id: "alias", ParentId: id("/spire/server"), SpiffeId: id(aliasPath), ExpiresAt: past}
	live := &types.Entry{Id: "live", ParentId: id(aliasPath), SpiffeId: id("/ns/orders/sa/api"), ExpiresAt: future}
	dead := &types.Entry{Id: "dead", ParentId: id(agent.Path()), SpiffeId: id("/ns/orders/sa/old"), ExpiresAt: past}
	child := &types.Entry{Id: "child", ParentId: dead.SpiffeId, SpiffeId: id("/child"), ExpiresAt: future}
	cache := &FullEntryCache{
		entries: map[string][]*types.Entry{
			agent.Path():       {dead},
			dead.SpiffeId.Path: {child},
			aliasPath:          {live},
		},
		aliases: map[string][]aliasEntry{
			agent.Path(): {{id: aliasPath, entry: expiredAlias}},
		},
	}
	if got := cache.GetAuthorizedEntries(agent); len(got) != 0 {
		t.Fatalf("expired registration authorized %d entries", len(got))
	}
	expiredAlias.ExpiresAt = future
	got := cache.GetAuthorizedEntries(agent)
	if len(got) != 1 || got[0].GetId() != "live" {
		t.Fatalf("renewed alias authorized %d entries", len(got))
	}
	found := cache.LookupAuthorizedEntries(agent, map[string]struct{}{"dead": {}, "child": {}, "live": {}})
	if _, ok := found["live"]; !ok || len(found) != 1 {
		t.Fatalf("lookup returned %d entries", len(found))
	}
}
