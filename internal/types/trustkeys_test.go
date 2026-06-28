package types

import (
	"crypto/ed25519"
	"testing"
)

// signedCC signs a cluster config under the given key.
func signedCC(t *testing.T, cc *ClusterConfig, priv ed25519.PrivateKey, keyID string) *Signed {
	t.Helper()
	s, err := Sign(priv, keyID, "cluster-config", cc)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A pre-split config (no TrustKeys) verifies against its GrantKeys: the fallback
// keeps already-deployed fleets working when TrustKeys is absent.
func TestTrustKeysAbsentFallsBackToGrantKeys(t *testing.T) {
	pub, priv, keyID, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	cc := &ClusterConfig{ConfigVersion: 1, GrantKeys: []GrantKey{{KeyID: keyID, PublicKey: pub}}}
	trust, err := cc.TrustedConfigKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyClusterConfig(trust, signedCC(t, cc, priv, keyID), 0); err != nil {
		t.Fatalf("absent TrustKeys must verify via GrantKeys: %v", err)
	}
}

// The headline property: once TrustKeys is present and distinct from GrantKeys, a
// config signed by the GRANT key alone is rejected — a running controller (which
// holds only its grant key) cannot rewrite the fleet trust set. The trust key
// must sign it.
func TestTrustKeysRejectGrantOnlySignature(t *testing.T) {
	gPub, gPriv, gID, _ := GenerateSigningKey()
	tPub, tPriv, tID, _ := GenerateSigningKey()
	cc := &ClusterConfig{
		ConfigVersion: 1,
		GrantKeys:     []GrantKey{{KeyID: gID, PublicKey: gPub}},
		TrustKeys:     []TrustKey{{KeyID: tID, PublicKey: tPub}},
	}
	trust, err := cc.TrustedConfigKeys() // = the trust set, NOT the grant set
	if err != nil {
		t.Fatal(err)
	}
	// signed by the grant key -> rejected
	if _, err := VerifyClusterConfig(trust, signedCC(t, cc, gPriv, gID), 0); err == nil {
		t.Fatal("a config signed only by the grant key must be rejected when TrustKeys is present")
	}
	// signed by the trust key -> accepted
	if _, err := VerifyClusterConfig(trust, signedCC(t, cc, tPriv, tID), 0); err != nil {
		t.Fatalf("a config signed by the trust key must verify: %v", err)
	}
	// the grant set still verifies grants only — confirm it does NOT verify the config
	grantSet, _ := cc.TrustedKeys()
	if _, err := VerifyClusterConfig(grantSet, signedCC(t, cc, gPriv, gID), 0); err != nil {
		t.Fatalf("sanity: the grant set itself still verifies a grant-key signature: %v", err)
	}
}

// Two-version overlap: TrustKeys may list both the old and new key during a
// rotation, so a config signed by either verifies; an unlisted key does not.
func TestTrustKeysRotationOverlap(t *testing.T) {
	oPub, oPriv, oID, _ := GenerateSigningKey()
	nPub, nPriv, nID, _ := GenerateSigningKey()
	_, xPriv, xID, _ := GenerateSigningKey() // an unlisted third key
	cc := &ClusterConfig{
		ConfigVersion: 5,
		GrantKeys:     []GrantKey{{KeyID: oID, PublicKey: oPub}},
		TrustKeys:     []TrustKey{{KeyID: oID, PublicKey: oPub}, {KeyID: nID, PublicKey: nPub}},
	}
	trust, _ := cc.TrustedConfigKeys()
	if _, err := VerifyClusterConfig(trust, signedCC(t, cc, oPriv, oID), 0); err != nil {
		t.Fatalf("old trust key must verify during overlap: %v", err)
	}
	if _, err := VerifyClusterConfig(trust, signedCC(t, cc, nPriv, nID), 0); err != nil {
		t.Fatalf("new trust key must verify during overlap: %v", err)
	}
	if _, err := VerifyClusterConfig(trust, signedCC(t, cc, xPriv, xID), 0); err == nil {
		t.Fatal("an unlisted key must not verify")
	}
}
