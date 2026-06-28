package controller

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"geneza.io/internal/policy"
)

// Per-workspace policy lives in the durable store (the HA SQL store in a
// multi-replica deployment), so a workspace admin can edit their own policy from
// the console and every replica converges on it. The on-disk policy_file is only
// a one-time SEED: the first time a workspace is loaded with no stored policy,
// the file is parsed, written into the store, and thereafter the store is the
// source of truth. This keeps single-node file deployments working (they seed
// themselves on first boot) while making policy a per-tenant, editable record.

const workspacePolicySettingPrefix = "workspace_policy/"

func workspacePolicyKey(ws string) string { return workspacePolicySettingPrefix + ws }

// workspacePolicyRecord is the stored form: the policy document plus who last
// edited it (surfaced in the console so an admin can see provenance).
type workspacePolicyRecord struct {
	Doc         string `json:"doc"`
	UpdatedBy   string `json:"updated_by"`
	UpdatedUnix int64  `json:"updated_unix"`
}

func getStoredWorkspacePolicy(store Store, ws string) (workspacePolicyRecord, bool, error) {
	b, err := store.GetSetting(workspacePolicyKey(ws))
	if err != nil {
		return workspacePolicyRecord{}, false, err
	}
	if len(b) == 0 {
		return workspacePolicyRecord{}, false, nil
	}
	var rec workspacePolicyRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return workspacePolicyRecord{}, false, fmt.Errorf("decode stored policy for %q: %w", ws, err)
	}
	return rec, true, nil
}

func putStoredWorkspacePolicy(store Store, ws string, rec workspacePolicyRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return store.SetSetting(workspacePolicyKey(ws), b)
}

// loadOrSeedWorkspacePolicyDoc returns a workspace's policy document, seeding it
// from seedFile into the store on first use. The returned bytes are always a
// store-validated policy doc.
func loadOrSeedWorkspacePolicyDoc(store Store, ws, seedFile string) ([]byte, workspacePolicyRecord, error) {
	if rec, ok, err := getStoredWorkspacePolicy(store, ws); err != nil {
		return nil, workspacePolicyRecord{}, err
	} else if ok {
		return []byte(rec.Doc), rec, nil
	}
	if seedFile == "" {
		return nil, workspacePolicyRecord{}, fmt.Errorf("workspace %q has no stored policy and no seed policy_file", ws)
	}
	b, err := os.ReadFile(seedFile)
	if err != nil {
		return nil, workspacePolicyRecord{}, fmt.Errorf("seed policy for %q (%s): %w", ws, seedFile, err)
	}
	if _, err := policy.Parse(b); err != nil {
		return nil, workspacePolicyRecord{}, fmt.Errorf("seed policy for %q (%s): %w", ws, seedFile, err)
	}
	rec := workspacePolicyRecord{Doc: string(b), UpdatedBy: "bootstrap", UpdatedUnix: time.Now().Unix()}
	if err := putStoredWorkspacePolicy(store, ws, rec); err != nil {
		return nil, workspacePolicyRecord{}, err
	}
	return b, rec, nil
}

// buildPolicyEngines builds one policy engine per workspace, sourcing each from
// the store (seeding from the workspace's policy_file on first use). Covers both
// config-declared workspaces and store-only (auto-provisioned) tenants.
func buildPolicyEngines(store Store, cfg *Config) (map[string]policy.Engine, error) {
	engines := make(map[string]policy.Engine)
	build := func(ws, seedFile string) error {
		doc, _, err := loadOrSeedWorkspacePolicyDoc(store, ws, seedFile)
		if err != nil {
			return err
		}
		eng, err := policy.Parse(doc)
		if err != nil {
			return fmt.Errorf("workspace %q policy: %w", ws, err)
		}
		engines[ws] = eng
		return nil
	}
	for _, w := range cfg.Workspaces {
		if err := build(w.ID, w.PolicyFile); err != nil {
			return nil, err
		}
	}
	wss, err := store.ListWorkspaces()
	if err != nil {
		return nil, fmt.Errorf("list store workspaces: %w", err)
	}
	for _, w := range wss {
		if engines[w.ID] != nil {
			continue
		}
		if err := build(w.ID, cfg.autoProvisionPolicyFile()); err != nil {
			return nil, err
		}
	}
	return engines, nil
}

// workspaceSeedFile resolves the seed policy_file for a workspace: a config
// workspace uses its own (defaulted to the top-level), others the auto-provision
// policy.
func (s *Server) workspaceSeedFile(ws string) string {
	for _, w := range s.cfg.Workspaces {
		if w.ID == ws {
			return w.PolicyFile
		}
	}
	return s.cfg.autoProvisionPolicyFile()
}

// GetWorkspacePolicy returns the workspace's current policy document and edit
// metadata, seeding from the policy_file if the store has none yet.
func (s *Server) GetWorkspacePolicy(ws string) ([]byte, workspacePolicyRecord, error) {
	return loadOrSeedWorkspacePolicyDoc(s.store, ws, s.workspaceSeedFile(ws))
}

// SetWorkspacePolicy validates a new policy document, persists it to the store,
// and hot-swaps the workspace's engine. Validation failure leaves both the store
// and the live engine untouched (fail closed), so a bad edit can never widen
// access.
func (s *Server) SetWorkspacePolicy(ws string, doc []byte, actor string) error {
	eng, err := policy.Parse(doc)
	if err != nil {
		return err
	}
	rec := workspacePolicyRecord{Doc: string(doc), UpdatedBy: actor, UpdatedUnix: time.Now().Unix()}
	if err := putStoredWorkspacePolicy(s.store, ws, rec); err != nil {
		return err
	}
	s.policyMu.Lock()
	if s.policyEngines == nil {
		s.policyEngines = map[string]policy.Engine{}
	}
	s.policyEngines[ws] = eng
	s.policyMu.Unlock()
	if s.audit != nil {
		_ = s.audit.Append("policy_edit", actor, "", "", map[string]string{"workspace": ws})
	}
	return nil
}
