package relay

import (
	"bytes"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

func TestRegionAuthHandler(t *testing.T) {
	const secret = "topsecret"
	secrets := map[string]RegionSecret{"eu": {Current: secret}}
	h := regionAuthHandler("eu", secrets, logging.NewDefaultLoggerFactory().NewLogger("test"))

	// A credential minted for this region's current secret validates, and the
	// integrity key the handler derives matches the one the client computed.
	user, pass, err := turn.GenerateLongTermTURNRESTCredentials(secret, "eu:abc", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	uid, key, ok := h(&turn.RequestAttributes{Username: user, Realm: "geneza"})
	if !ok || uid != user {
		t.Fatalf("valid eu credential rejected: ok=%v uid=%q", ok, uid)
	}
	if !bytes.Equal(key, turn.GenerateAuthKey(user, "geneza", pass)) {
		t.Fatal("derived integrity key does not match the minted credential")
	}

	// A credential tagged for another region is rejected even though the secret is
	// the same — region containment caps a leaked secret to its own region.
	foreign, _, _ := turn.GenerateLongTermTURNRESTCredentials(secret, "us:abc", time.Hour)
	if _, _, ok := h(&turn.RequestAttributes{Username: foreign, Realm: "geneza"}); ok {
		t.Fatal("a credential for a foreign region must be rejected")
	}

	// An expired credential is rejected.
	expired, _, _ := turn.GenerateLongTermTURNRESTCredentials(secret, "eu:abc", -time.Hour)
	if _, _, ok := h(&turn.RequestAttributes{Username: expired, Realm: "geneza"}); ok {
		t.Fatal("an expired credential must be rejected")
	}

	// A malformed (untagged) username is rejected.
	if _, _, ok := h(&turn.RequestAttributes{Username: "12345:onlyone", Realm: "geneza"}); ok {
		t.Fatal("a username without a region tag must be rejected")
	}
}
