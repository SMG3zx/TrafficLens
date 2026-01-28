// app/login/login-card.tsx
"use client";

import * as React from "react";
import Link from "next/link";
import { Github, KeyRound, Mail, Eye, EyeOff } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";

export default function LoginCard() {
  const [showPassword, setShowPassword] = React.useState(false);
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  async function handleCredentialsLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      // If redirect: true, NextAuth will navigate.
      // If you set redirect: false, you can check res?.error here.
      return res;
    } catch (err: any) {
      setError(err?.message ?? "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="border-white/10 bg-white/5 text-white shadow-[0_0_0_1px_rgba(255,255,255,0.06)] backdrop-blur">
      <CardContent className="p-6">
        <div className="space-y-3">
          <Button
            type="button"
            variant="secondary"
            className="w-full justify-center gap-2 rounded-xl bg-white/5 text-white hover:bg-white/10 border border-white/10"
          >
            <Github className="h-4 w-4" />
            Log in with GitHub
          </Button>

          <Button
            type="button"
            variant="secondary"
            className="w-full justify-center gap-2 rounded-xl bg-white/5 text-white hover:bg-white/10 border border-white/10"
          >
            {/* simple “G” dot — replace with your own if you want */}
            <span className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-white/10 text-xs font-semibold">
              G
            </span>
            Log in with Google
          </Button>

          <Button
            type="button"
            variant="secondary"
            className="w-full justify-center gap-2 rounded-xl bg-white/5 text-white hover:bg-white/10 border border-white/10"
          >
            <KeyRound className="h-4 w-4" />
            Log in with SSO
          </Button>
        </div>

        <div className="my-6 flex items-center gap-4">
          <Separator className="flex-1 bg-white/10" />
          <span className="text-xs text-white/50">or</span>
          <Separator className="flex-1 bg-white/10" />
        </div>

        <form onSubmit={handleCredentialsLogin} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email" className="text-white/80">
              Email
            </Label>
            <div className="relative">
              <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/35" />
              <Input
                id="email"
                type="email"
                placeholder=""
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="h-11 rounded-xl bg-black/20 border-white/10 text-white pl-10 focus-visible:ring-0 focus-visible:ring-offset-0"
                autoComplete="email"
              />
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="password" className="text-white/80">
                Password
              </Label>
              <Link
                href="/forgot-password"
                className="text-sm text-white/50 hover:text-white/80"
              >
                Forgot password?
              </Link>
            </div>

            <div className="relative">
              <Input
                id="password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="h-11 rounded-xl bg-black/20 border-white/10 text-white pr-10 focus-visible:ring-0 focus-visible:ring-offset-0"
                autoComplete="current-password"
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

          {error ? <p className="text-sm text-red-300">{error}</p> : null}

          <Button
            type="submit"
            className="mt-2 h-11 w-full rounded-xl bg-blue-600 hover:bg-blue-500"
            disabled={loading}
          >
            {loading ? "Logging in..." : "Log in"}
          </Button>
        </form>
      </CardContent>

      <CardFooter className="border-t border-white/10 px-6 py-4">
        <p className="w-full text-center text-sm text-white/70">
          Don't have an account?{" "}
          <Link href="/signup" className="text-sky-400 hover:text-sky-300">
            Sign up for free!
          </Link>
        </p>
      </CardFooter>
    </Card>
  );
}
