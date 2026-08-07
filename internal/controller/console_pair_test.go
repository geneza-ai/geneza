package controller

import "testing"

// A workspace may bind several projects, so pairing needs exactly one to know which
// project to stamp — guessing would silently put a node in the wrong tenancy.
func TestWorkspaceOpenStackBinding(t *testing.T) {
	srv := newUniquenessTestServer(t)

	bind := func(key, ws string) {
		t.Helper()
		if err := srv.store.PutSourceBinding(&SourceBinding{Key: key, WorkspaceID: ws}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("no binding is an error, not an empty project", func(t *testing.T) {
		if _, _, err := srv.workspaceOpenStackBinding("default"); err == nil {
			t.Fatal("an unbound workspace returned a project")
		}
	})

	t.Run("one binding yields cloud and project", func(t *testing.T) {
		bind("openstack:project:acvile:71f5edaa1c1d4ffb88406b608e052cb3", "default")
		svc, proj, err := srv.workspaceOpenStackBinding("default")
		if err != nil {
			t.Fatal(err)
		}
		if svc != "acvile" || proj != "71f5edaa1c1d4ffb88406b608e052cb3" {
			t.Fatalf("got (%q,%q)", svc, proj)
		}
	})

	t.Run("non-OpenStack bindings are ignored", func(t *testing.T) {
		bind("idp:group:geneza:eng", "default")
		if _, _, err := srv.workspaceOpenStackBinding("default"); err != nil {
			t.Fatalf("an idp binding confused the lookup: %v", err)
		}
	})

	t.Run("several projects is ambiguous and refused", func(t *testing.T) {
		bind("openstack:project:acvile:another-project-uuid", "default")
		if _, _, err := srv.workspaceOpenStackBinding("default"); err == nil {
			t.Fatal("a workspace binding two projects silently picked one")
		}
	})
}

// The trusted os:project must come from the workspace's binding, never from what
// the machine claims — otherwise a node could talk its way into a project its
// workspace does not reach. The claim is only checked for agreement.
func TestPairingDerivesProjectFromTheBindingNotTheClaim(t *testing.T) {
	srv := newUniquenessTestServer(t)
	const (
		ws       = "default"
		bound    = "71f5edaa1c1d4ffb88406b608e052cb3"
		instance = "af78268f-32e9-4a96-b9c0-92fee3fe286f"
	)
	if err := srv.store.PutSourceBinding(&SourceBinding{
		Key: "openstack:project:acvile:" + bound, WorkspaceID: ws,
	}); err != nil {
		t.Fatal(err)
	}

	svc, proj, err := srv.workspaceOpenStackBinding(ws)
	if err != nil {
		t.Fatal(err)
	}

	// What the handler stamps, given a node claiming a DIFFERENT project. The
	// handler refuses that case outright; this asserts that even the values it would
	// write come from the binding.
	labels := map[string]string{
		claimedInstanceLabel: instance,
		claimedProjectLabel:  "a-project-the-node-made-up",
	}
	labels[launchInstanceLabel] = labels[claimedInstanceLabel]
	labels[launchProjectLabel] = proj
	labels[osCloudLabel] = svc

	if labels[launchProjectLabel] != bound {
		t.Fatalf("os:project = %q, want the bound project %q", labels[launchProjectLabel], bound)
	}
	if labels[launchProjectLabel] == labels[claimedProjectLabel] {
		t.Fatal("os:project was taken from the node's claim")
	}

	// Pairing must not become a way around the one-node-per-instance rule.
	if err := srv.store.PutNode(ws, &NodeRecord{
		ID: "n-other", Name: "other",
		Labels: map[string]string{launchInstanceLabel: instance, osCloudLabel: svc},
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.enforceInstanceUniqueness(ws, labels); err == nil {
		t.Fatal("pairing bypassed the uniqueness rule enrollment enforces")
	}
}
