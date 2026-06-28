// Command geneza-desktop is the cross-platform Wails desktop client. It renders
// the existing React console (web/) in the OS-native webview and binds
// DesktopService, which drives the shared client core in-process — so the remote
// shell runs the same direct end-to-end tunnel as `geneza ssh`, not the
// controller-proxied browser path. Headless servers use the CLI; this module lives
// outside the root module so its webview/CGO deps never touch the CLI build.
package main

import (
	"embed"
	"net/http"
	"strings"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	svc := NewDesktopService()
	if err := wails.Run(&options.App{
		Title:     "Geneza",
		Width:     1280,
		Height:    832,
		MinWidth:  960,
		MinHeight: 640,
		AssetServer: &assetserver.Options{
			Assets: assets,
			// Route the embedded console's /api/v1 calls to the controller over mTLS;
			// everything else is the embedded frontend.
			Middleware: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasPrefix(r.URL.Path, "/api/v1/") {
						// The native shell runs over the direct tunnel (bindings), so
						// never proxy the controller-brokered web-shell broker (client_path
						// =web, which require_native policy is meant to deny).
						if strings.Contains(r.URL.Path, "/shell") {
							http.Error(w, "not available in the desktop app", http.StatusNotFound)
							return
						}
						svc.serveAPI(w, r)
						return
					}
					next.ServeHTTP(w, r)
				})
			},
		},
		OnStartup:  svc.startup,
		OnShutdown: svc.shutdown,
		Bind:       []any{svc},
	}); err != nil {
		println("geneza desktop:", err.Error())
	}
}
