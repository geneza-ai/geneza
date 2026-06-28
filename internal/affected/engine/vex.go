package engine

import "sync"

// MemVEX is a minimal in-memory VEXSource: a set of (workspace, cve, purl)
// statements that mark a component not_affected with a justification. It is the
// concrete suppression input the engine consults today; full OpenVEX document
// ingestion is a later increment that can implement the same VEXSource interface.
type MemVEX struct {
	mu    sync.RWMutex
	stmts map[string]string // key -> justification
}

// NewMemVEX builds an empty in-memory VEX source.
func NewMemVEX() *MemVEX { return &MemVEX{stmts: map[string]string{}} }

func vexKey(ws, cve, purl string) string { return ws + "\x00" + cve + "\x00" + purl }

// Set records a not_affected statement for (ws, cve, purl) with the given
// justification, overwriting any prior one.
func (v *MemVEX) Set(ws, cve, purl, justification string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.stmts[vexKey(ws, cve, purl)] = justification
}

// Suppressed reports whether a statement clears (ws, cve, purl).
func (v *MemVEX) Suppressed(ws, cve, purl string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	j, ok := v.stmts[vexKey(ws, cve, purl)]
	return j, ok
}

var _ VEXSource = (*MemVEX)(nil)
