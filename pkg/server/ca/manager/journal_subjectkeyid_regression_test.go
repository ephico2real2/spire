package manager

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeserverkeymanager"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func regressionRFC7093ID(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	var s struct {
		Algorithm pkix.AlgorithmIdentifier
		Public    asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &s)
	require.NoError(t, err)
	require.Empty(t, rest)
	sum := sha256.Sum256(s.Public.Bytes)
	return sum[:20]
}

func regressionJournalCertificate(t *testing.T, signer crypto.Signer, skid []byte) *x509.Certificate {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(17), Subject: pkix.Name{CommonName: "SPIRE retained CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: skid}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(raw)
	require.NoError(t, err)
	return cert
}

func regressionJournalFixture(t *testing.T, kind keymanager.KeyType) (*journalConfig, *fakedatastore.DataStore, keymanager.Key) {
	t.Helper()
	km := fakeserverkeymanager.New(t)
	k, err := km.GenerateKey(context.Background(), "x509-CA-A", kind)
	require.NoError(t, err)
	ds := fakedatastore.New(t)
	cat := fakeservercatalog.New()
	cat.SetKeyManager(km)
	cat.SetDataStore(ds)
	log, _ := logtest.NewNullLogger()
	return &journalConfig{cat: cat, log: log}, ds, k
}

func regressionSaveJournal(t *testing.T, ds *fakedatastore.DataStore, cert *x509.Certificate, entries ...*journal.X509CAEntry) *datastore.CAJournal {
	t.Helper()
	id := x509util.SubjectKeyIDToString(cert.SubjectKeyId)
	if entries == nil {
		entries = []*journal.X509CAEntry{{SlotId: "A", IssuedAt: time.Now().Add(-time.Minute).Unix(), NotAfter: cert.NotAfter.Unix(), Certificate: cert.Raw, Status: journal.Status_ACTIVE, AuthorityId: id}}
	}
	raw, err := proto.Marshal(&journal.Entries{X509CAs: entries})
	require.NoError(t, err)
	record, err := ds.SetCAJournal(context.Background(), &datastore.CAJournal{Data: raw, ActiveX509AuthorityID: id})
	require.NoError(t, err)
	return record
}

// This test uses only existing upstream interfaces and compiles before the fix.
// Under ordinary non-FIPS SPIRE it fails before the patch with zero recovered CAs.
func TestJournalRFC7093SubjectKeyIDRecovery(t *testing.T) {
	for _, kind := range []keymanager.KeyType{keymanager.ECP256, keymanager.RSA2048} {
		t.Run(kind.String(), func(t *testing.T) {
			config, ds, k := regressionJournalFixture(t, kind)
			cert := regressionJournalCertificate(t, k, regressionRFC7093ID(t, k.Public()))
			record := regressionSaveJournal(t, ds, cert)
			loaded, err := LoadJournal(context.Background(), config)
			require.NoError(t, err)
			require.Len(t, loaded.getEntries().X509CAs, 1, "must recover the existing CA rather than prepare a replacement")
			require.Equal(t, cert.Raw, loaded.getEntries().X509CAs[0].Certificate)
			require.Equal(t, record.ID, loaded.caJournalID)
			// Repeated startup does not create a replacement journal or key.
			again, err := LoadJournal(context.Background(), config)
			require.NoError(t, err)
			require.Equal(t, record.ID, again.caJournalID)
			all, err := ds.ListCAJournalsForTesting(context.Background())
			require.NoError(t, err)
			require.Len(t, all, 1)
			keys, err := config.cat.GetKeyManager().GetKeys(context.Background())
			require.NoError(t, err)
			require.Len(t, keys, 1)
			require.True(t, publicKeyEqual(k.Public(), keys[0].Public()))
		})
	}
}

func TestJournalNativeSubjectKeyIDRemainsRecoverable(t *testing.T) {
	config, ds, k := regressionJournalFixture(t, keymanager.ECP256)
	skid, err := x509util.GetSubjectKeyID(k.Public())
	require.NoError(t, err)
	cert := regressionJournalCertificate(t, k, skid)
	record := regressionSaveJournal(t, ds, cert)
	got, err := LoadJournal(context.Background(), config)
	require.NoError(t, err)
	require.Equal(t, record.ID, got.caJournalID)
	require.Len(t, got.getEntries().X509CAs, 1)
}

func TestJournalHashCollisionDoesNotAdoptDifferentPublicKey(t *testing.T) {
	config, ds, k := regressionJournalFixture(t, keymanager.ECP256)
	other, err := keymanager.ECP256.GenerateSigner()
	require.NoError(t, err)
	// Synthetically collide the stored identifier while retaining a different SPKI.
	cert := regressionJournalCertificate(t, other, regressionRFC7093ID(t, k.Public()))
	regressionSaveJournal(t, ds, cert)
	got, err := LoadJournal(context.Background(), config)
	require.ErrorContains(t, err, "does not match managed public key")
	require.Nil(t, got)
	all, err := ds.ListCAJournalsForTesting(context.Background())
	require.NoError(t, err)
	require.Len(t, all, 1, "failure must not rewrite or remove existing journals")
}

func TestJournalDuplicateActiveCertificateIsRefused(t *testing.T) {
	config, ds, k := regressionJournalFixture(t, keymanager.ECP256)
	cert := regressionJournalCertificate(t, k, regressionRFC7093ID(t, k.Public()))
	id := x509util.SubjectKeyIDToString(cert.SubjectKeyId)
	entry := &journal.X509CAEntry{SlotId: "A", NotAfter: cert.NotAfter.Unix(), Certificate: cert.Raw, Status: journal.Status_ACTIVE, AuthorityId: id}
	regressionSaveJournal(t, ds, cert, entry, entry)
	got, err := LoadJournal(context.Background(), config)
	require.ErrorContains(t, err, "exactly one")
	require.Nil(t, got)
}

func TestJournalMissingActiveCertificateIsRefused(t *testing.T) {
	config, ds, k := regressionJournalFixture(t, keymanager.ECP256)
	cert := regressionJournalCertificate(t, k, regressionRFC7093ID(t, k.Public()))
	regressionSaveJournal(t, ds, cert, &journal.X509CAEntry{SlotId: "A", Certificate: cert.Raw, AuthorityId: "unrelated"})
	got, err := LoadJournal(context.Background(), config)
	require.ErrorContains(t, err, "exactly one")
	require.Nil(t, got)
}

func TestJournalNonCAAndMalformedCertificateAreRefused(t *testing.T) {
	for _, raw := range [][]byte{[]byte("malformed"), nil} {
		t.Run(string(raw), func(t *testing.T) {
			config, ds, k := regressionJournalFixture(t, keymanager.ECP256)
			cert := regressionJournalCertificate(t, k, regressionRFC7093ID(t, k.Public()))
			id := x509util.SubjectKeyIDToString(cert.SubjectKeyId)
			regressionSaveJournal(t, ds, cert, &journal.X509CAEntry{SlotId: "A", Certificate: raw, AuthorityId: id})
			got, err := LoadJournal(context.Background(), config)
			require.ErrorContains(t, err, "unable to parse active journal CA")
			require.Nil(t, got)
		})
	}
}

func TestJournalMultipleManagedAuthoritiesDoNotSelectArbitraryHistory(t *testing.T) {
	config, ds, a := regressionJournalFixture(t, keymanager.ECP256)
	b, err := config.cat.GetKeyManager().GenerateKey(context.Background(), "x509-CA-B", keymanager.ECP256)
	require.NoError(t, err)
	for _, k := range []keymanager.Key{a, b} {
		cert := regressionJournalCertificate(t, k, regressionRFC7093ID(t, k.Public()))
		regressionSaveJournal(t, ds, cert)
	}
	got, err := LoadJournal(context.Background(), config)
	require.ErrorContains(t, err, "multiple CA journals")
	require.Nil(t, got)
	all, err := ds.ListCAJournalsForTesting(context.Background())
	require.NoError(t, err)
	require.Len(t, all, 2)
}

func TestJournalValidLeafCannotServeAsRetainedCA(t *testing.T) {
	config, ds, k := regressionJournalFixture(t, keymanager.ECP256)
	skid := regressionRFC7093ID(t, k.Public())
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(19), Subject: pkix.Name{CommonName: "not a CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: false, KeyUsage: x509.KeyUsageDigitalSignature, SubjectKeyId: skid}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, k.Public(), k)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(raw)
	require.NoError(t, err)
	regressionSaveJournal(t, ds, cert)
	got, err := LoadJournal(context.Background(), config)
	require.ErrorContains(t, err, "does not match managed public key and CA certificate")
	require.Nil(t, got)
}
