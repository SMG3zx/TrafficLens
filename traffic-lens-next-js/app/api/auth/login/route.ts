import { NextResponse } from "next/server"
import { signIn } from "@/lib/auth"

export async function POST(req: Request) {
  try {
    const { email, password } = (await req.json()) ?? {}
    const result = await signIn({ email, password })
    return NextResponse.json({ ok: true, user: result.user })
  } catch (e: any) {
    return new NextResponse(e?.message ?? "Login failed", { status: 401 })
  }
}