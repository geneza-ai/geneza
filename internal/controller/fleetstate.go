package controller

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"geneza.io/internal/defaults"
	"geneza.io/internal/types"
)

// Split-mode trust: the fleet trust set is two independently-signed documents.
// The offline/threshold-signed TrustAnchors names who is trusted; the online
// grant-key-signed RoutineMap carries the high-churn routing view bound to a
// specific anchor version+digest. A controller holding only a grant key re-signs the
// routine map freely but can never author trust anchors — that is the property
// that breaks the circular self-signing. An un-split (legacy) cluster has no
// anchor and keeps the single-envelope ClusterConfig path untouched.

// splitModeActive reports whether this controller's store holds offline/threshold
// trust anchors. False on a legacy (un-split) store, where the grant key is the
// implicit trust root and the legacy ClusterConfig path stays in force.
func splitModeActive(st Store) (bool, error) {
	_, _, anchorVersion, anchorSigned, err := st.FleetStateSnapshot()
	if err != nil {
		return false, err
	}
	return anchorVersion > 0 && len(anchorSigned) > 0, nil
}

// canAuthorAnchors is always false: a running controller holds only its online grant
// key, never an offline trust key, so it can never sign a TrustAnchors document.
// Authoring anchors is the offline geneza-trust threshold flow's job. Kept as a
// named predicate so the re-sign path reads as a deliberate refusal, not an
// omission.
func (s *Server) canAuthorAnchors() bool { return false }

// buildRoutineMap assembles the high-churn routing view bound to the held trust
// anchors: it carries the same relays/controller endpoints the legacy reconcile
// builds, plus the anchor version and digest the verifier checks. version is the
// routine-map ConfigVersion.
func buildRoutineMap(version int64, relays []types.RelayNode, controllers []types.ControllerEndpoint, relayAddrs []string, anchorVersion int64, anchorPayload []byte) types.RoutineMap {
	return types.RoutineMap{
		ConfigVersion:    version,
		AnchorVersion:    anchorVersion,
		AnchorDigest:     types.AnchorDigestOf(anchorPayload),
		RelayAddrs:       relayAddrs,
		Relays:           relays,
		ControllerEndpoints: controllers,
	}
}

// signRoutineMap signs a routine map online with the grant key. This is the ONLY
// fleet document a running controller authors in split mode; the trust anchors come
// from the offline/threshold flow and are merely carried forward.
func signRoutineMap(rm types.RoutineMap, key crypto.Signer, keyID string) ([]byte, error) {
	signed, err := types.Sign(key, keyID, defaults.ContextRoutineMap, rm)
	if err != nil {
		return nil, err
	}
	return signed.Encode()
}

// heldAnchors decodes the stored TrustAnchors envelope (without re-verifying it —
// it was verified when it was CASed in) into its parsed form and exact payload
// bytes, so a re-signed routine map can bind to the same anchor version + digest.
func heldAnchors(st Store) (*types.TrustAnchors, []byte, error) {
	_, _, anchorVersion, anchorSigned, err := st.FleetStateSnapshot()
	if err != nil {
		return nil, nil, err
	}
	if anchorVersion == 0 || len(anchorSigned) == 0 {
		return nil, nil, fmt.Errorf("no trust anchors in store (legacy mode)")
	}
	ms, err := types.DecodeMultiSigned(anchorSigned)
	if err != nil {
		return nil, nil, fmt.Errorf("stored trust anchors: %w", err)
	}
	var a types.TrustAnchors
	if err := json.Unmarshal(ms.Payload, &a); err != nil {
		return nil, nil, fmt.Errorf("stored trust anchors payload: %w", err)
	}
	return &a, ms.Payload, nil
}

// grantKeyAuthorized reports whether this controller's grant key is among the grant
// keys the held anchors authorize — i.e. whether it may sign the routine map at
// all. A controller whose key the anchors do not list must not re-sign (its routine
// map would be rejected fleet-wide); it keeps the offline-published map.
func grantKeyAuthorized(anchors *types.TrustAnchors, grantKeyID string) bool {
	for _, k := range anchors.GrantKeys {
		if k.KeyID == grantKeyID && len(k.PublicKey) == ed25519.PublicKeySize {
			return true
		}
	}
	return false
}

// reconcileRoutineMap is the split-mode counterpart of the legacy reconcile: it
// rebuilds the high-churn routing view, and — when this controller's grant key is
// authorized by the held anchors — re-signs it (bound to those anchors) and CASes
// it into the store under the cross-binding invariant. It NEVER touches the
// anchors: an anchor change is the offline geneza-trust threshold flow's job, so a
// stolen grant key cannot rewrite trust. A drift it cannot sign (its key is not in
// the anchors' grant set) is left to the offline publisher, mirroring the legacy
// canSignConfig refusal.
func (s *Server) reconcileRoutineMap() error {
	mapVersion, mapSigned, anchorVersion, anchorSigned, err := s.store.FleetStateSnapshot()
	if err != nil {
		return fmt.Errorf("fleet state: %w", err)
	}
	if anchorVersion == 0 || len(anchorSigned) == 0 {
		return fmt.Errorf("split reconcile with no stored anchors")
	}
	anchors, anchorPayload, err := heldAnchors(s.store)
	if err != nil {
		return err
	}

	relays := s.assembleRelays()
	controllers := s.assembleControllerEndpoints()
	candidate := buildRoutineMap(0, relays, controllers, s.cfg.RelayAddrs, anchorVersion, anchorPayload)

	// Drift compare ignores ConfigVersion, like the legacy path.
	var stored types.RoutineMap
	if len(mapSigned) > 0 {
		if env, derr := types.DecodeSigned(mapSigned); derr == nil {
			_ = json.Unmarshal(env.Payload, &stored)
		}
	}
	stored.ConfigVersion = 0
	candB, _ := json.Marshal(candidate)
	storedB, _ := json.Marshal(stored)
	if string(candB) == string(storedB) {
		s.setRoutineCache(mapVersion, relays, controllers, anchors, anchorSigned, mapSigned)
		return nil
	}

	// A controller whose grant key the anchors do not authorize must not re-sign — its
	// routine map would be rejected fleet-wide. Keep the published map.
	if !grantKeyAuthorized(anchors, s.grantKeyID) {
		s.setRoutineCache(mapVersion, relays, controllers, anchors, anchorSigned, mapSigned)
		return nil
	}

	// The anchors are carried forward verbatim — a running controller never authors
	// them. This is the structural guarantee the split exists for.
	if s.canAuthorAnchors() {
		return fmt.Errorf("a running controller must never author trust anchors")
	}
	newVersion := mapVersion + 1
	candidate.ConfigVersion = newVersion
	newSigned, err := signRoutineMap(candidate, s.grantKey, s.grantKeyID)
	if err != nil {
		return fmt.Errorf("sign routine map: %w", err)
	}
	// Advance the routine map only; the anchor stays as-is (anchorSigned nil), so the
	// store enforces the map binds to the current anchor.
	if err := s.store.SetSignedFleetState(newVersion, newSigned, anchorVersion, anchorVersion, nil); err != nil {
		if errors.Is(err, errClusterConfigConflict) {
			return nil // another controller advanced it; next tick re-checks drift
		}
		return err
	}
	s.setRoutineCache(newVersion, relays, controllers, anchors, anchorSigned, newSigned)
	s.registry.Broadcast(s.fleetControllerMsg())
	return nil
}

// splitLegacyConfig builds the legacy ClusterConfig a split-mode controller serves
// ALONGSIDE the split documents, so a node that has not yet pinned the anchors keeps
// adopting a normal grant-key-signed config during migration. It carries the same
// trust fields the anchors hold (grant keys, CA roots, agent policy, audit recipient)
// and the same routing view, but leaves TrustKeys empty: an un-pinned legacy node
// verifies it against the grant keys exactly as today, while a split-aware node pins
// from the anchor envelope instead. The grant key signs it (a routine document by
// trust-class — it carries no offline-only trust change). Returns nil when this
// controller's key is not authorized to sign (it then serves no fresh legacy fallback,
// only the published split docs).
func (s *Server) splitLegacyConfig(version int64, anchors *types.TrustAnchors, relays []types.RelayNode, controllers []types.ControllerEndpoint) []byte {
	// The require-split flip stops serving the legacy fallback entirely: only the
	// anchor + routine-map pair travels, so an un-pinned node must upgrade.
	if s.cfg.RequireSplitTrust {
		return nil
	}
	if !grantKeyAuthorized(anchors, s.grantKeyID) {
		return nil
	}
	pub, err := ed25519PublicKey(s.grantKey)
	if err != nil {
		return nil
	}
	cc := types.ClusterConfig{
		ConfigVersion:    version,
		CARootsPEM:       anchors.CARootsPEM,
		GrantKeys:        []types.GrantKey{{KeyID: s.grantKeyID, PublicKey: []byte(pub)}},
		AgentPolicy:      anchors.AgentPolicy,
		RelayAddrs:       s.cfg.RelayAddrs,
		Relays:           relays,
		ControllerEndpoints: controllers,
		AuditRecipient:   anchors.AuditRecipient,
		AuditRecipients:  anchors.AuditRecipients,
	}
	signed, err := signClusterConfig(cc, s.grantKey, s.grantKeyID)
	if err != nil {
		return nil
	}
	return signed
}

// installTrustAnchors ingests an operator-supplied, offline/threshold-signed
// TrustAnchors envelope and CASes it into the store, flipping the cluster into split
// mode (or advancing the anchor version on an already-split cluster). The controller
// holds NO trust key: it never authors or alters the anchor, only stores the one it
// is handed and re-pins a fresh routine map to it. It checks the envelope is
// self-consistent (the threshold is met against the anchor's OWN trust keys — the
// same dead-on-arrival guard geneza-trust assemble applies, so an operator cannot
// install an envelope a fleet would reject) and that this controller's grant key is
// authorized to sign the bound routine map (otherwise the map it produces would be
// rejected fleet-wide). It does NOT pin the anchor as a trust root — nodes do that,
// from their own held set; the controller is a payload-faithful store. Returns the
// anchor version now in force and the routine-map version re-pinned to it.
func (s *Server) installTrustAnchors(anchorBytes []byte) (anchorVersion, configVersion int64, err error) {
	ms, err := types.DecodeMultiSigned(anchorBytes)
	if err != nil {
		return 0, 0, fmt.Errorf("decode trust anchors: %w", err)
	}
	var anchors types.TrustAnchors
	if err := json.Unmarshal(ms.Payload, &anchors); err != nil {
		return 0, 0, fmt.Errorf("trust anchors payload: %w", err)
	}
	if anchors.AnchorVersion < 1 {
		return 0, 0, fmt.Errorf("trust anchors must carry anchor_version >= 1, got %d", anchors.AnchorVersion)
	}
	// Self-consistency: the supplied signatures must meet the document's own threshold
	// against its own trust keys. The controller cannot validate WHO should be trusted
	// (it holds no offline key) — that is the operator's custody decision — but it
	// refuses an envelope that is internally short of its own threshold.
	pinned, err := anchors.PinnedTrustKeys()
	if err != nil {
		return 0, 0, err
	}
	if _, err := types.VerifyMultiSig(pinned, anchors.Threshold, defaults.ContextTrustAnchors, ms, nil); err != nil {
		return 0, 0, fmt.Errorf("trust anchors do not meet their own threshold: %w", err)
	}
	// A canonical re-marshal must round-trip to the signed bytes, so the digest a node
	// binds the routine map to (sha256 of these exact payload bytes) is reproducible.
	if reb, _ := json.Marshal(&anchors); string(reb) != string(ms.Payload) {
		return 0, 0, errors.New("trust anchors payload is not canonical (re-marshal differs)")
	}
	// This controller must be able to sign the routine map bound to the new anchors, else
	// the map it CASes in would be rejected fleet-wide.
	if !grantKeyAuthorized(&anchors, s.grantKeyID) {
		return 0, 0, fmt.Errorf("trust anchors do not authorize this controller's grant key %s; install on an authorized controller", s.grantKeyID)
	}
	if s.canAuthorAnchors() {
		return 0, 0, errors.New("a running controller must never author trust anchors")
	}

	mapVersion, _, curAnchorVersion, _, err := s.store.FleetStateSnapshot()
	if err != nil {
		return 0, 0, fmt.Errorf("fleet state: %w", err)
	}
	if anchors.AnchorVersion != curAnchorVersion+1 {
		return 0, 0, fmt.Errorf("trust anchors version %d does not follow the stored anchor version %d", anchors.AnchorVersion, curAnchorVersion)
	}

	relays := s.assembleRelays()
	controllers := s.assembleControllerEndpoints()
	newConfigVersion := mapVersion + 1
	rm := buildRoutineMap(newConfigVersion, relays, controllers, s.cfg.RelayAddrs, anchors.AnchorVersion, ms.Payload)
	mapSigned, err := signRoutineMap(rm, s.grantKey, s.grantKeyID)
	if err != nil {
		return 0, 0, fmt.Errorf("sign routine map: %w", err)
	}
	// Advance the routine map AND the anchor in one CAS: the map binds to the new
	// anchor version, so the store's cross-binding invariant holds.
	if err := s.store.SetSignedFleetState(newConfigVersion, mapSigned, anchors.AnchorVersion, anchors.AnchorVersion, anchorBytes); err != nil {
		return 0, 0, err
	}
	s.setRoutineCache(newConfigVersion, relays, controllers, &anchors, anchorBytes, mapSigned)
	s.registry.Broadcast(s.fleetControllerMsg())
	return anchors.AnchorVersion, newConfigVersion, nil
}

// setRoutineCache updates the in-memory routing caches the broker reads and the
// documents served to agents/relays, from a verified/re-signed routine map. It is
// the split-mode analogue of setClusterConfig: it caches the split anchor+map
// envelopes (served to pinned nodes) AND a fresh legacy fallback config (served to
// un-pinned nodes), so a routine churn refreshes the served bytes rather than leaving
// a stale legacy blob behind.
func (s *Server) setRoutineCache(version int64, relays []types.RelayNode, controllers []types.ControllerEndpoint, anchors *types.TrustAnchors, anchorSigned, mapSigned []byte) {
	legacy := s.splitLegacyConfig(version, anchors, relays, controllers)
	s.ccMu.Lock()
	defer s.ccMu.Unlock()
	if version < s.ccVersion {
		return
	}
	s.ccVersion = version
	s.ccRelays = relays
	s.ccControllers = controllers
	s.ccAuditRecipient = anchors.AuditRecipient
	s.ccAuditRecipients = anchors.EffectiveAuditRecipients()
	s.ccAnchorSigned = anchorSigned
	s.ccRoutineSigned = mapSigned
	// Refresh the legacy fallback so a served config in split mode is never the stale
	// pre-split blob. A controller not authorized to sign keeps the last legacy config it
	// held (it cannot mint a fresh one) but still serves the fresh split pair. Under the
	// require-split flip no legacy fallback is served at all.
	switch {
	case s.cfg.RequireSplitTrust:
		s.ccSigned = nil
	case legacy != nil:
		s.ccSigned = legacy
	}
}
