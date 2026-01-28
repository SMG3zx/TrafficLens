// app/forgot-password/page.tsx
import ForgotPasswordCard from "./forgot-password-card"

export default function ForgotPasswordPage() {
  return (
    <div className="relative min-h-dvh bg-black text-white">
      {/* background glow */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-24 h-[520px] w-[520px] -translate-x-1/2 rounded-full bg-white/10 blur-3xl" />
        <div className="absolute left-1/2 top-32 h-[320px] w-[700px] -translate-x-1/2 rounded-full bg-white/5 blur-3xl" />
      </div>

      <div className="relative mx-auto flex min-h-dvh max-w-md items-center px-6 py-12">
        <div className="w-full">
          <div className="mb-8 text-center">
            <div className="text-4xl font-semibold tracking-tight text-sky-400">
              TrafficLens
            </div>
          </div>

          <ForgotPasswordCard />
        </div>
      </div>
    </div>
  )
}
