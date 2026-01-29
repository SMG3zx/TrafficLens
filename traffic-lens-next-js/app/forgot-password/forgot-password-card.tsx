// app/forgot-password/forgot-password-card.tsx
"use client"

import * as React from "react"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"

export default function ForgotPasswordCard() {
  const [email, setEmail] = React.useState("")
  const [loading, setLoading] = React.useState(false)
  const [done, setDone] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setDone(false)
    setLoading(true)

    try {
      const res = await fetch("/api/auth/password/forgot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      })

      // Important security pattern: always respond “ok” even if email not found.
      if (!res.ok) {
        const text = await res.text()
        throw new Error(text || "Could not start password recovery")
      }

      setDone(true)
    } catch (err: any) {
      setError(err?.message ?? "Something went wrong")
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card className="border-white/10 bg-white/5 text-white shadow-[0_0_0_1px_rgba(255,255,255,0.06)] backdrop-blur">
      <CardHeader className="px-6 py-5">
        <div className="text-2xl font-semibold">Reset Password</div>
      </CardHeader>

      <Separator className="bg-white/10" />

      <CardContent className="p-6">
        <form onSubmit={onSubmit} className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="email" className="text-white/80">
              Email
            </Label>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="h-11 rounded-xl bg-black/20 border-white/10 text-white focus-visible:ring-0 focus-visible:ring-offset-0"
              autoComplete="email"
            />
          </div>

          {error ? <p className="text-sm text-red-300">{error}</p> : null}
          {done ? (
            <p className="text-sm text-emerald-300">
              If an account exists for that email, we sent a recovery link.
            </p>
          ) : null}

          <div className="flex justify-end">
            <Button
              type="submit"
              className="h-11 rounded-xl bg-blue-600 hover:bg-blue-500 px-8"
              disabled={loading || !email}
            >
              {loading ? "Sending..." : "Recover Password"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
