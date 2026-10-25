package manager

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/private/server/journal"
	"google.golang.org/protobuf/proto"
)

// journalAuthorityIDs is a bounded compatibility lookup, not a change to the
// SKID generated for new SPIRE certificates. Go 1.25+ upstream signers can issue
// RFC7093 IDs even when SPIRE's current runtime uses RFC5280 IDs.
// The native ID remains first. SHA1 is never called here in FIPS-only mode.
func journalAuthorityIDs(public crypto.PublicKey) ([]string, error) {
	native, err := x509util.GetSubjectKeyID(public)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, err
	}
	var info struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(spki, &info)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("decode managed public key")
	}
	sum := sha256.Sum256(info.SubjectPublicKey.Bytes)
	ids := []string{x509util.SubjectKeyIDToString(native)}
	other := x509util.SubjectKeyIDToString(sum[:20])
	if ids[0] != other {
		ids = append(ids, other)
	}
	return ids, nil
}

// verifyJournalManagedKey does not authorize an arbitrary hash-selected record.
// The exact active certificate, authority ID and complete SPKI must match the
// managed public key. Existing SlotLoader retains its slot/key, bundle, expiry
// and preparation checks; this helper does not import or mutate any key.
func verifyJournalManagedKey(record *datastore.CAJournal, authorityID string, public crypto.PublicKey) error {
	if record == nil || record.ID == 0 || record.ActiveX509AuthorityID != authorityID || len(record.Data) == 0 || len(record.Data) > 1024*1024 {
		return fmt.Errorf("invalid CA journal identity or size")
	}
	entries := new(journal.Entries)
	if err := proto.Unmarshal(record.Data, entries); err != nil {
		return fmt.Errorf("unable to unmarshal entries from CA journal record: %w", err)
	}
	expected, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return err
	}
	matched := 0
	for _, entry := range entries.X509CAs {
		if entry.AuthorityId != authorityID {
			continue
		}
		cert, err := x509.ParseCertificate(entry.Certificate)
		if err != nil {
			return fmt.Errorf("unable to parse active journal CA certificate: %w", err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 || len(cert.UnhandledCriticalExtensions) != 0 || len(cert.SubjectKeyId) == 0 || x509util.SubjectKeyIDToString(cert.SubjectKeyId) != authorityID || !bytes.Equal(cert.RawSubjectPublicKeyInfo, expected) {
			return fmt.Errorf("journal active authority does not match managed public key and CA certificate")
		}
		matched++
	}
	if matched != 1 {
		return fmt.Errorf("journal must contain exactly one matching active CA certificate")
	}
	return nil
}
