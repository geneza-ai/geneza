// Package sbom is the shared CycloneDX layer the inventory collector and the
// controller both speak: the agent encodes its collected packages into a CycloneDX
// JSON document, and the controller decodes that same document back into the flat
// component view its matcher joins against. Keeping one encode/decode pair in a
// leaf package means the two ends can never drift on the wire shape, the PURL
// conventions, or where the OSV ecosystem and distro live.
//
// The bytes that travel and that the controller stores are zstd-compressed; Compress
// and Decompress are here so the transport, the store, and the hash all agree on
// the canonical (uncompressed) document.
package sbom

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/klauspost/compress/zstd"

	"geneza.io/internal/purl"
)

// MediaType is the CycloneDX JSON media type recorded as the stored SBOM's format.
const MediaType = "application/vnd.cyclonedx+json"

// propEcosystem carries the OSV ecosystem string (e.g. "Ubuntu:22.04", "npm") on a
// component, set authoritatively by the collector. The matcher needs the
// distro-scoped ecosystem to pick the backport-aware advisory, and a bare PURL type
// ("deb") does not encode the distro release — so the collector records it rather
// than the controller guessing.
const propEcosystem = "geneza:osv:ecosystem"

// propDistro carries the distro identifier (e.g. "ubuntu:22.04") so the matcher
// compares an installed version against the distro's own backported fixed version.
const propDistro = "geneza:os:distro"

// propSource records which collector origin a component came from ("os" for an OS
// package, "lang" for a language dependency), part of a component's identity in the
// store so the same purl from two origins does not collide.
const propSource = "geneza:source"

// Component is one package the collector found: a PURL plus the OSV ecosystem and
// distro the matcher needs. Ecosystem is the OSV ecosystem string; Distro is set
// only for OS packages. Source is the collection origin.
type Component struct {
	Purl      string
	Name      string
	Version   string
	Ecosystem string
	Distro    string
	Source    string
}

// Encode renders the components into a CycloneDX 1.5 JSON document. nodeID names
// the subject in the BOM metadata so a stored SBOM is self-describing. The OSV
// ecosystem, distro, and source ride as component properties (CycloneDX's
// extension point) so the controller reads them back authoritatively instead of
// re-deriving them from the PURL.
func Encode(nodeID string, comps []Component) ([]byte, error) {
	// Encode in a canonical order so the content hash is a function of the component
	// SET, not the order the collectors happened to emit them in. Both ends need this:
	// the controller re-derives the same hash after applying a delta to the set it holds,
	// and an unchanged inventory must hash identically across re-collections.
	comps = sortedComponents(comps)
	out := make([]cdx.Component, 0, len(comps))
	for _, c := range comps {
		comp := cdx.Component{
			Type:       cdx.ComponentTypeLibrary,
			Name:       c.Name,
			Version:    c.Version,
			PackageURL: c.Purl,
		}
		var props []cdx.Property
		if c.Ecosystem != "" {
			props = append(props, cdx.Property{Name: propEcosystem, Value: c.Ecosystem})
		}
		if c.Distro != "" {
			props = append(props, cdx.Property{Name: propDistro, Value: c.Distro})
		}
		if c.Source != "" {
			props = append(props, cdx.Property{Name: propSource, Value: c.Source})
		}
		if len(props) > 0 {
			comp.Properties = &props
		}
		out = append(out, comp)
	}
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Component: &cdx.Component{Type: cdx.ComponentTypeContainer, Name: nodeID, BOMRef: nodeID},
	}
	bom.Components = &out

	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(false)
	if err := enc.Encode(bom); err != nil {
		return nil, fmt.Errorf("encode cyclonedx: %w", err)
	}
	return buf.Bytes(), nil
}

// Extract decodes a CycloneDX JSON document into the flat component view, walking
// nested components (a container image's packages are a subtree) so every package
// surfaces. A component is kept only when it carries a PURL the matcher can key on;
// the ecosystem/distro come from the collector's properties when present and are
// otherwise derived from the PURL. This is the bridge the controller's component index
// and matcher are built on, so it is deliberately permissive about which fields the
// producer set and strict about producing a usable (ecosystem, name, version).
func Extract(doc []byte) ([]Component, error) {
	doc = clampSpecVersion(doc)
	var bom cdx.BOM
	dec := cdx.NewBOMDecoder(bytes.NewReader(doc), cdx.BOMFileFormatJSON)
	if err := dec.Decode(&bom); err != nil {
		return nil, fmt.Errorf("decode cyclonedx: %w", err)
	}
	var out []Component
	var walk func(comps *[]cdx.Component)
	walk = func(comps *[]cdx.Component) {
		if comps == nil {
			return
		}
		for i := range *comps {
			c := (*comps)[i]
			if pc, ok := componentFrom(c); ok {
				out = append(out, pc)
			}
			walk(c.Components)
		}
	}
	walk(bom.Components)
	return out, nil
}

// maxSupportedSpecVersion is the highest CycloneDX spec the bundled decoder
// understands.
const maxSupportedSpecVersion = "1.6"

// supportedSpecVersions are the spec versions the bundled decoder accepts; a
// document declaring anything else (a scanner ahead of us, e.g. trivy emitting
// 1.7) is clamped to maxSupportedSpecVersion before decoding.
var supportedSpecVersions = map[string]bool{
	"1.0": true, "1.1": true, "1.2": true, "1.3": true,
	"1.4": true, "1.5": true, "1.6": true,
}

// clampSpecVersion rewrites a CycloneDX document's specVersion to the highest
// version the decoder supports when the declared version is newer (or otherwise
// unrecognized). The component fields the collector reads — purl, name, version,
// properties — are stable across these revisions, so a scanner that has moved to a
// newer spec is read rather than rejected outright.
func clampSpecVersion(doc []byte) []byte {
	var head struct {
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(doc, &head); err != nil || head.SpecVersion == "" || supportedSpecVersions[head.SpecVersion] {
		return doc
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(doc, &m); err != nil {
		return doc
	}
	v, err := json.Marshal(maxSupportedSpecVersion)
	if err != nil {
		return doc
	}
	m["specVersion"] = v
	out, err := json.Marshal(m)
	if err != nil {
		return doc
	}
	return out
}

// componentFrom lifts one CycloneDX component into the flat view. It returns
// ok=false for a component with no PURL (a grouping/metadata node), which the
// matcher cannot key. ecosystem/distro/source are read from the collector's
// properties first; ecosystem and name/version fall back to the PURL so a SBOM
// produced by another tool (no geneza properties) still matches.
func componentFrom(c cdx.Component) (Component, bool) {
	if c.PackageURL == "" {
		return Component{}, false
	}
	props := propMap(c.Properties)
	pc := Component{
		Purl:      c.PackageURL,
		Name:      c.Name,
		Version:   c.Version,
		Ecosystem: props[propEcosystem],
		Distro:    props[propDistro],
		Source:    props[propSource],
	}
	pu, err := purl.Parse(c.PackageURL)
	if err == nil {
		if pc.Name == "" {
			pc.Name = pu.Name
		}
		if pc.Version == "" {
			pc.Version = pu.Version
		}
		if pc.Ecosystem == "" {
			pc.Ecosystem = pu.Ecosystem
		}
		if pc.Distro == "" {
			pc.Distro = pu.Distro
		}
	}
	if pc.Source == "" {
		pc.Source = "os"
	}
	return pc, pc.Ecosystem != "" && pc.Name != ""
}

func propMap(props *[]cdx.Property) map[string]string {
	m := map[string]string{}
	if props == nil {
		return m
	}
	for _, p := range *props {
		m[p.Name] = p.Value
	}
	return m
}

// Hash is the canonical content hash the heartbeat carries and the controller stores:
// SHA-256 over the uncompressed CycloneDX document, so an unchanged inventory never
// re-uploads the blob.
func Hash(doc []byte) [32]byte { return sha256.Sum256(doc) }

// Compress zstd-compresses the canonical document for transport and storage.
func Compress(doc []byte) ([]byte, error) {
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	return enc.EncodeAll(doc, nil), nil
}

// Decompress reverses Compress, recovering the canonical CycloneDX document.
func Decompress(blob []byte) ([]byte, error) {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return dec.DecodeAll(blob, nil)
}

// componentKey is a component's identity for set membership and diffing: the same
// (purl, source) pair the controller's component index is keyed on, so the same package
// reported from two origins is two members and a re-collection of the same package
// is one stable member.
func componentKey(c Component) [2]string { return [2]string{c.Purl, c.Source} }

// sortedComponents returns a copy ordered by (purl, source) so encoding is
// deterministic regardless of collector order.
func sortedComponents(comps []Component) []Component {
	out := make([]Component, len(comps))
	copy(out, comps)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Purl != out[j].Purl {
			return out[i].Purl < out[j].Purl
		}
		return out[i].Source < out[j].Source
	})
	return out
}

// Diff computes the change from base to next as the components to add and to remove,
// keyed by (purl, source). It is the agent's delta-builder: added are the members in
// next but not base, removed are the members in base but not next. A member whose
// version changed surfaces in BOTH (removed at the old version, added at the new),
// which is what lets a delta carry a version bump.
func Diff(base, next []Component) (added, removed []Component) {
	baseSet := make(map[[2]string]Component, len(base))
	for _, c := range base {
		baseSet[componentKey(c)] = c
	}
	nextSet := make(map[[2]string]Component, len(next))
	for _, c := range next {
		nextSet[componentKey(c)] = c
	}
	for _, c := range next {
		prev, ok := baseSet[componentKey(c)]
		if !ok || prev != c {
			added = append(added, c)
		}
	}
	for _, c := range base {
		nc, ok := nextSet[componentKey(c)]
		if !ok || nc != c {
			removed = append(removed, c)
		}
	}
	return sortedComponents(added), sortedComponents(removed)
}

// Apply reconstructs a component set from a base set plus a delta: it drops every
// removed member (by identity) and adds/overwrites every added one. It is the
// controller's delta-applier, the inverse of Diff — Apply(base, Diff(base, next)) yields
// next as a set. The result is canonically ordered so the caller can re-encode and
// re-hash it to verify the delta landed on the expected base.
func Apply(base, added, removed []Component) []Component {
	set := make(map[[2]string]Component, len(base))
	for _, c := range base {
		set[componentKey(c)] = c
	}
	for _, c := range removed {
		delete(set, componentKey(c))
	}
	for _, c := range added {
		set[componentKey(c)] = c
	}
	out := make([]Component, 0, len(set))
	for _, c := range set {
		out = append(out, c)
	}
	return sortedComponents(out)
}
