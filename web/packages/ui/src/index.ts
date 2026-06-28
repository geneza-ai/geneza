// @geneza/ui — the Geneza design system.
//
// The theme itself (Tailwind v4 tokens + self-hosted fonts) is the CSS entry,
// imported separately by each app's index.css:
//
//   @import "@geneza/ui/theme.css";
//
// This module is the code entry: the shared `cn` helper plus the primitives
// both consoles share. App-specific components stay in their app.

export { cn } from "./lib/cn"

export { Button, buttonVariants, type ButtonProps } from "./components/ui/button"
export {
  Card,
  CardHeader,
  CardFooter,
  CardTitle,
  CardDescription,
  CardContent,
} from "./components/ui/card"
export { Skeleton } from "./components/ui/skeleton"
