import { api } from "@/api"
import type { NodeModule } from "@/types"

/**
 * Toggle ONE module on a node without clobbering the others.
 *
 * `PUT /api/v1/nodes/{id}/modules` is replace-not-merge, so sending a
 * single-element array deletes every other module's stored config. That is not a
 * cosmetic problem: the inventory module's settings (`scan_root`,
 * `lang_scan_roots`, `scan_interval_seconds`) have no other write path in the
 * product — there is no CLI flag for them — so a monitoring toggle silently
 * destroyed configuration the operator could only set through this same endpoint.
 * It also resurrects a deliberately-disabled module, because the controller merges
 * defaults over whatever it is given.
 *
 * This mirrors `setNodeModuleMerged` in cmd/geneza/inventory.go, which is the CLI's
 * long-standing fix for exactly the same trap.
 */
export async function setNodeModuleMerged(
  nodeId: string,
  name: string,
  enabled: boolean,
  settings?: Record<string, string>
): Promise<void> {
  const current = await api.getNodeModules(nodeId)
  const modules = current.modules ?? []
  let found = false
  const next: NodeModule[] = modules.map((m) => {
    if (m.name !== name) return m
    found = true
    // Preserve the module's existing settings unless the caller supplies new ones;
    // a toggle is not an instruction to reset configuration.
    return { name, enabled, settings: settings ?? m.settings }
  })
  if (!found) next.push({ name, enabled, settings })
  await api.setNodeModules(nodeId, next)
}
