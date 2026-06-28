import { Activity } from "lucide-react"

export function Splash({ label }: { label?: string }) {
  return (
    <div className="flex min-h-screen w-full flex-col items-center justify-center gap-3 bg-background">
      <div className="flex size-10 animate-pulse items-center justify-center rounded-xl bg-primary text-primary-foreground">
        <Activity className="size-5" />
      </div>
      {label && (
        <p className="text-sm text-muted-foreground">{label}</p>
      )}
    </div>
  )
}
