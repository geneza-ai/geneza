import { GenezaMark } from "@geneza/ui"

export function Splash({ label }: { label?: string }) {
  return (
    <div className="flex min-h-screen w-full flex-col items-center justify-center gap-3 bg-background">
      <GenezaMark size={40} className="animate-pulse" />
      {label && (
        <p className="text-sm text-muted-foreground">{label}</p>
      )}
    </div>
  )
}
