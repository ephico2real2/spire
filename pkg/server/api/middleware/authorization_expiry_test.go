package middleware_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/authpolicy"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestRegistrationExpiryDeniesNewPrivilegedRPCsBeforePrune(t *testing.T) {
	for _, role := range []struct {
		name              string
		admin, downstream bool
		methods           []string
	}{
		{name: "admin", admin: true, methods: []string{
			"/spire.api.server.svid.v1.SVID/MintX509SVID",
			"/spire.api.server.svid.v1.SVID/MintJWTSVID",
			"/spire.api.server.svid.v1.SVID/MintWITSVID",
			"/spire.api.server.entry.v1.Entry/BatchUpdateEntry",
		}},
		{name: "downstream", downstream: true, methods: []string{
			"/spire.api.server.svid.v1.SVID/NewDownstreamX509CA",
			"/spire.api.server.bundle.v1.Bundle/PublishJWTAuthority",
			"/spire.api.server.bundle.v1.Bundle/PublishWITAuthority",
		}},
	} {
		t.Run(role.name, func(t *testing.T) {
			id := spiffeid.RequireFromString("spiffe://example.org/leased-role")
			grant := &types.Entry{Id: "grant", Admin: role.admin, Downstream: role.downstream}
			ordinary := &types.Entry{Id: "ordinary", ExpiresAt: time.Now().Add(time.Hour).Unix()}
			fetches := 0
			fetcher := middleware.EntryFetcherFunc(func(context.Context, spiffeid.ID) ([]*types.Entry, error) {
				fetches++
				// The expired row remains present. Do not simulate pruning.
				return []*types.Entry{grant, ordinary}, nil
			})
			engine, err := authpolicy.DefaultAuthPolicy(context.Background())
			require.NoError(t, err)
			authorization := middleware.WithAuthorization(engine, fetcher, noAgentAuthorizer, nil)
			log, _ := test.NewNullLogger()
			certificate := &x509.Certificate{
				URIs:      []*url.URL{id.URL()},
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(2 * time.Hour),
			}
			incoming := peer.NewContext(rpccontext.WithLogger(context.Background(), log), &peer.Peer{
				Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
				AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
					HandshakeComplete: true,
					PeerCertificates:  []*x509.Certificate{certificate},
				}},
			})
			for _, state := range []struct {
				name   string
				expiry int64
				code   codes.Code
			}{
				{"current", time.Now().Add(time.Hour).Unix(), codes.OK},
				{"expired", time.Now().Add(-time.Hour).Unix(), codes.PermissionDenied},
				{"still expired on another new request", time.Now().Add(-time.Hour).Unix(), codes.PermissionDenied},
				{"renewed", time.Now().Add(time.Hour).Unix(), codes.OK},
				{"legacy zero expiry", 0, codes.OK},
			} {
				t.Run(state.name, func(t *testing.T) {
					grant.ExpiresAt = state.expiry
					for _, method := range role.methods {
						result, err := authorization.Preprocess(incoming, method, nil)
						require.Equal(t, state.code, status.Code(err), method)
						if state.code == codes.OK {
							require.NotNil(t, result)
							if role.downstream {
								entries, ok := rpccontext.CallerDownstreamEntries(result)
								require.True(t, ok)
								require.Equal(t, []*types.Entry{grant}, entries)
							}
						} else {
							require.Nil(t, result)
						}
					}
					require.True(t, time.Now().Before(certificate.NotAfter))
				})
			}
			require.Equal(t, len(role.methods)*5, fetches)
		})
	}
}
