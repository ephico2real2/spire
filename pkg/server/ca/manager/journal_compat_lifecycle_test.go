package manager

import (
	"context"
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeserverkeymanager"
	"github.com/stretchr/testify/require"
)

// Journal lookup binds identity; existing SlotLoader owns status eligibility.
// Do not require ACTIVE here: crashes during rotation and pre-status journals
// must retain their exact certificate/history rather than silently start fresh.
func TestJournalCompatibilityPreservesRotationAndLegacyStatuses(t *testing.T) {
	for _, status := range []journal.Status{journal.Status_UNKNOWN, journal.Status_PREPARED, journal.Status_ACTIVE, journal.Status_OLD} {
		t.Run(status.String(), func(t *testing.T) {
			config, ds, k := regressionJournalFixture(t, keymanager.ECP256)
			cert := regressionJournalCertificate(t, k, regressionRFC7093ID(t, k.Public()))
			id := x509util.SubjectKeyIDToString(cert.SubjectKeyId)
			record := regressionSaveJournal(t, ds, cert, &journal.X509CAEntry{SlotId: "A", NotAfter: cert.NotAfter.Unix(), Certificate: cert.Raw, Status: status, AuthorityId: id})
			loaded, err := LoadJournal(context.Background(), config)
			require.NoError(t, err)
			require.Equal(t, record.ID, loaded.caJournalID)
			require.Len(t, loaded.getEntries().X509CAs, 1)
			require.Equal(t, status, loaded.getEntries().X509CAs[0].Status)
		})
	}
}

// Two HA servers use one datastore but separate KeyManager key ownership. Equal
// slot names must not allow either server to adopt the other's journal.
func TestJournalCompatibilitySharedDatastoreSeparateHAKeyManagers(t *testing.T) {
	ds := fakedatastore.New(t)
	configs := make([]*journalConfig, 2)
	ids := make([]uint, 2)
	keys := make([]keymanager.Key, 2)
	for i := range 2 {
		km := fakeserverkeymanager.New(t)
		// Each fake KeyManager starts the same deterministic key stream.
		// Advance the second stream by overwriting the SAME fixture slot;
		// adding a discard slot would expose the first server's key in GetKeys.
		var k keymanager.Key
		for generation := 0; generation <= i; generation++ {
			var err error
			k, err = km.GenerateKey(context.Background(), "x509-CA-A", keymanager.ECP256)
			require.NoError(t, err)
		}
		keys[i] = k
		cat := fakeservercatalog.New()
		cat.SetKeyManager(km)
		cat.SetDataStore(ds)
		log, _ := logtest.NewNullLogger()
		configs[i] = &journalConfig{cat: cat, log: log}
		cert := regressionJournalCertificate(t, k, regressionRFC7093ID(t, k.Public()))
		ids[i] = regressionSaveJournal(t, ds, cert).ID
	}
	require.NotEqual(t, ids[0], ids[1])
	require.False(t, publicKeyEqual(keys[0].Public(), keys[1].Public()), "HA fixtures must own different full public keys")
	for i, config := range configs {
		loaded, err := LoadJournal(context.Background(), config)
		require.NoError(t, err)
		require.Equal(t, ids[i], loaded.caJournalID)
		require.Len(t, loaded.getEntries().X509CAs, 1)
	}
	all, err := ds.ListCAJournalsForTesting(context.Background())
	require.NoError(t, err)
	require.Len(t, all, 2)
}
