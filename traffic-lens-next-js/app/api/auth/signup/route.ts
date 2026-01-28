import { NextResponse } from "next/server"
import { signUp } from "@/lib/auth"

export async function POST(req: Request) {
  try {
    const { name, email, password } = (await req.json()) ?? {}
    const result = await signUp({ name, email, password, autoSignIn: true })
    return NextResponse.json({ ok: true, user: result.user })
  } catch (e: any) {
    return new NextResponse(e?.message ?? "Signup failed", { status: 400 })
  }
}
