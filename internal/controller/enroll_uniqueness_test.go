package controller

import (
	"strings"
	"testing"
)

func newUniquenessTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := testServerConfig(t)
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}
	if err := InitDataDir(cfg); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}

// resolveLaunchNode returns the FIRST node whose os:instance matches, in store
// order. So without a uniqueness constraint the label is not an identity: a second
// node wearing the same instance competes for that VM's shell sessions, and which
// one wins is not something the operator chose. docs/openstack-integration.md §10
// step 5 requires refusing a second live node for a UUID.
func TestEnrollRefusesADuplicateInstance(t *testing.T) {
	srv := newUniquenessTestServer(t)
	const (
		ws       = "default"
		instance = "af78268f-32e9-4a96-b9c0-92fee3fe286f"
	)

	seed := func(id, name string, labels map[string]string) {
		t.Helper()
		if err := srv.store.PutNode(ws, &NodeRecord{ID: id, Name: name, Labels: labels}); err != nil {
			t.Fatal(err)
		}
	}
	seed("n-existing", "web-01", map[string]string{
		launchInstanceLabel: instance, osCloudLabel: "acvile",
	})

	t.Run("second node for the same instance on the same cloud is refused", func(t *testing.T) {
		err := srv.enforceInstanceUniqueness(ws, map[string]string{
			launchInstanceLabel: instance, osCloudLabel: "acvile",
		})
		if err == nil {
			t.Fatal("a second node claimed an already-enrolled instance; launches would " +
				"go to whichever the store happened to list first")
		}
		// The operator has to be able to act on it, so name the node in the way.
		if !strings.Contains(err.Error(), "web-01") || !strings.Contains(err.Error(), "retire") {
			t.Errorf("message should name the conflicting node and the remedy, got: %v", err)
		}
	})

	t.Run("same UUID on a different cloud is a different instance", func(t *testing.T) {
		// Instance UUIDs are unique only within one Nova (residual risk #22).
		if err := srv.enforceInstanceUniqueness(ws, map[string]string{
			launchInstanceLabel: instance, osCloudLabel: "other-cloud",
		}); err != nil {
			t.Fatalf("a collision across clouds was treated as a duplicate: %v", err)
		}
	})

	t.Run("a node with no instance label is unaffected", func(t *testing.T) {
		if err := srv.enforceInstanceUniqueness(ws, map[string]string{"env": "prod"}); err != nil {
			t.Fatalf("a non-OpenStack node was refused: %v", err)
		}
	})

	t.Run("a different instance enrolls normally", func(t *testing.T) {
		if err := srv.enforceInstanceUniqueness(ws, map[string]string{
			launchInstanceLabel: "11111111-2222-3333-4444-555555555555", osCloudLabel: "acvile",
		}); err != nil {
			t.Fatalf("an unrelated instance was refused: %v", err)
		}
	})

	// The legitimate re-enrollment flow retires first, so the slot is free.
	t.Run("re-enrolling after retiring the old node succeeds", func(t *testing.T) {
		if err := srv.store.DeleteNode(ws, "n-existing"); err != nil {
			t.Fatal(err)
		}
		if err := srv.enforceInstanceUniqueness(ws, map[string]string{
			launchInstanceLabel: instance, osCloudLabel: "acvile",
		}); err != nil {
			t.Fatalf("re-enrollment after retirement was refused: %v", err)
		}
	})
}
