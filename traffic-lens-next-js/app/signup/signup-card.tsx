"use client"

import * as React from "react"
import Link from "next/link"
import { signIn } from "next-auth/react"
import { Github, Eye, EyeOff } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter, CardHeader } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Checkbox } from "@/components/ui/checkbox"

export default function SignUpCard() {
  const [showPassword, setShowPassword] = React.useState(false)
  const [name, setName] = React.useState("")
  const [email, setEmail] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [accepted, setAccepted] = React.useState(false)
  const [loading, setLoading] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)

  async function handleSignup(e: React.FormEvent) {
    e.preventDefault()
    setError(null)

    if (!accepted) {
      setError("You must accept the terms to continue.")
      return
    }

    setLoading(true)
    try {
      // TODO: create your user via API route
      // POST /api/signup { name, email, password }
      const res = await fetch("/api/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password }),
      })

      if (!res.ok) {
        const msg = await res.text()
        throw new Error(msg || "Sign up failed")
      }

      // Optional: auto-login via NextAuth credentials after signup
      await signIn("credentials", {
        email,
        password,
        callbackUrl: "/",
      })
    } catch (err: any) {
      setError(err?.message ?? "Sign up failed")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <Card className="border-white/10 bg-white/5 text-white shadow-[0_0_0_1px_rgba(255,255,255,0.06)] backdrop-blur">
        <CardHeader className="px-6 py-5">
          <div className="text-2xl font-semibold">Sign up</div>
        </CardHeader>

        <Separator className="bg-white/10" />

        <CardContent className="p-6">
          <form onSubmit={handleSignup} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name" className="text-white/80">
                Name
              </Label>
              <Input
                id="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="h-11 rounded-xl bg-black/20 border-white/10 text-white focus-visible:ring-0 focus-visible:ring-offset-0"
                autoComplete="name"
              />
            </div>

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

            <div className="space-y-2">
              <Label htmlFor="password" className="text-white/80">
                Password
              </Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="h-11 rounded-xl bg-black/20 border-white/10 text-white pr-10 focus-visible:ring-0 focus-visible:ring-offset-0"
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((s) => !s)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-white/45 hover:text-white/75"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>

            <div className="flex items-start gap-3 pt-1">
              <Checkbox
                id="terms"
                checked={accepted}
                onCheckedChange={(v) => setAccepted(v === true)}
                className="mt-1 border-white/20 data-[state=checked]:bg-blue-600 data-[state=checked]:border-blue-600"
              />
              <Label htmlFor="terms" className="text-sm text-white/70 leading-5">
                I accept the{" "}
                <Link href="/terms" className="text-sky-400 hover:text-sky-300">
                  terms of service
                </Link>{" "}
                and{" "}
                <Link href="/privacy" className="text-sky-400 hover:text-sky-300">
                  privacy policy
                </Link>
              </Label>
            </div>

            {error ? <p className="text-sm text-red-300">{error}</p> : null}

            <Button
              type="submit"
              className="mt-2 h-11 w-full rounded-xl bg-blue-600 hover:bg-blue-500"
              disabled={loading}
            >
              {loading ? "Signing up..." : "Sign up"}
            </Button>
          </form>

          <div className="my-6 flex items-center gap-4">
            <Separator className="flex-1 bg-white/10" />
            <span className="text-xs text-white/50">or</span>
            <Separator className="flex-1 bg-white/10" />
          </div>

          <div className="space-y-3">
            <Button
              type="button"
              variant="secondary"
              className="w-full justify-center gap-2 rounded-xl bg-white/5 text-white hover:bg-white/10 border border-white/10"
              onClick={() => signIn("github", { callbackUrl: "/" })}
            >
              <Github className="h-4 w-4" />
              Sign up with GitHub
            </Button>

            <Button
              type="button"
              variant="secondary"
              className="w-full justify-center gap-2 rounded-xl bg-white/5 text-white hover:bg-white/10 border border-white/10"
              onClick={() => signIn("google", { callbackUrl: "/" })}
            >
              <span className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-white/10 text-xs font-semibold">
                G
              </span>
              Sign up with Google
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* bottom callout + button */}
      <div className="text-center space-y-3">
        <p className="text-sm text-white/70">Already have an account?</p>
        <Button
          asChild
          variant="secondary"
          className="rounded-xl bg-white/5 text-white hover:bg-white/10 border border-white/10"
        >
          <Link href="/login">Log in here!</Link>
        </Button>
      </div>
    </div>
  )
}
