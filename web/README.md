# Geneza web

npm-workspaces monorepo for every Geneza web surface and the shared design
system.

```
web/
  packages/
    ui/         @geneza/ui — design system (theme + fonts) + shared primitives
  apps/
    console/    @geneza/console — operator/tenant console (full feature set)
    cluster/    @geneza/cluster — cluster-operator console (topology / risk / agents)
```

Both apps are React 19 + Vite 8 + Tailwind CSS v4. The Go controller serves each
app's built `dist/` from a configured `static_dir` (the consoles are not
Go-embedded); the Wails desktop client embeds the console build (see
`../desktop`).

## Develop

```sh
npm install                 # once, from web/ — installs all workspaces
npm run dev:console         # operator console on :5173, proxies /api -> :8443
npm run dev:cluster         # cluster console, proxies /clusterconsole -> :7407
```

## Build

```sh
npm run build               # builds both apps -> apps/<name>/dist
npm run build:console
npm run build:cluster
```

## Shared UI

The theme and shared primitives live in **`packages/ui`** (`@geneza/ui`). The
theme is currently the **stock shadcn** Tailwind v4 setup (`src/theme.css`) — a
neutral base to build a real design system on later. Apps consume it with a
single CSS import:

```css
/* apps/<name>/src/index.css */
@import "@geneza/ui/theme.css";
```

and import shared primitives from the package root:

```ts
import { Button, Card, Skeleton, cn } from "@geneza/ui"
```
