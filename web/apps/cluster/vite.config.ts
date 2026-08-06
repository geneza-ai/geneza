import fs from "node:fs"
import https from "node:https"
import path from "path"
import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@geneza/ui": path.resolve(__dirname, "../../packages/ui/src"),
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    proxy: {
      // The cluster-console listener is mTLS-only (clusterConsoleServer serves
      // TLS with an optional client cert), so a plain http:// target here could
      // never connect — `npm run dev:cluster` proxied to a dead port and nobody
      // could run this app locally without editing this file.
      //
      // secure:false accepts the controller's Geneza-CA cert, which no browser
      // trust store knows about. Auth still has to come from somewhere: either an
      // OIDC session, or point GENEZA_CLUSTER_DEV_CERT/KEY at a break-glass admin
      // keypair and the proxy will present it.
      "/clusterconsole": {
        target: process.env.GENEZA_CLUSTER_DEV_URL ?? "https://localhost:7407",
        changeOrigin: true,
        secure: false,
        ...(process.env.GENEZA_CLUSTER_DEV_CERT && process.env.GENEZA_CLUSTER_DEV_KEY
          ? {
              agent: new https.Agent({
                cert: fs.readFileSync(process.env.GENEZA_CLUSTER_DEV_CERT),
                key: fs.readFileSync(process.env.GENEZA_CLUSTER_DEV_KEY),
                rejectUnauthorized: false,
              }),
            }
          : {}),
      },
    },
  },
})
