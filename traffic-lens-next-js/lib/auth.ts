import {cookies, headers} from "next/headers";
import { NextResponse } from "next/server";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import {prisma} from "@/lib/prisma"

const SESSION_COOKIE = "session_token"
const SESSION_DAYS = 7

function now(){
    return new Date()
}

function addDays(date: Date, days: number){
    const newDate = new Date(date)
    newDate.setDate(newDate.getDate()+ days)
    return newDate
}

function sha256(input: string){
    return crypto.createHash("sha256").update(input).digest("hex")
}

function newSessionToken(){
    return crypto.randomBytes(32).toString("hex")
}

function cookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
  }
}

export type AuthUser = {
  id: string
  email: string
  name: string | null
}

export type AuthSession = {
  user: AuthUser
  expiresAt: Date
}

export async function getSession(): Promise<AuthSession | null> {
  const token = (await cookies()).get(SESSION_COOKIE)?.value
  if (!token) return null

  const tokenHash = sha256(token)

  const session = await prisma.session.findUnique({
    where: { tokenHash },
    include: { user: true },
  })

  if (!session) return null
  if (session.expiresAt <= now()) {
    // expired: cleanup
    await prisma.session.delete({ where: { id: session.id } }).catch(() => {})
    return null
  }

  return {
    user: {
      id: session.user.id,
      email: session.user.email,
      name: session.user.name,
    },
    expiresAt: session.expiresAt,
  }
}

/** Require a logged-in user (throws) */
export async function requireUser(): Promise<AuthUser> {
  const sess = await getSession()
  if (!sess) throw new Error("UNAUTHORIZED")
  return sess.user
}

/**
 * Create a user and optionally log them in.
 * (Better Auth-ish signature)
 */
export async function signUp(input: {
  name?: string
  email: string
  password: string
  autoSignIn?: boolean
}) {
  const email = input.email.toLowerCase().trim()

  if (!email) throw new Error("Email is required")
  if (typeof input.password !== "string" || input.password.length < 8) {
    throw new Error("Password must be at least 8 characters")
  }

  const existing = await prisma.user.findUnique({ where: { email } })
  if (existing) throw new Error("Email already in use")

  const passwordHash = await bcrypt.hash(input.password, 12)

  const user = await prisma.user.create({
    data: {
      email,
      name: input.name?.trim() || null,
      passwordHash,
    },
  })

  if (input.autoSignIn) {
    await createSessionForUser(user.id)
  }

  return { user: { id: user.id, email: user.email, name: user.name } }
}

/**
 * Email/password sign in that sets cookie-based session.
 */
export async function signIn(input: { email: string; password: string }) {
  const email = input.email.toLowerCase().trim()
  const user = await prisma.user.findUnique({ where: { email } })
  if (!user) throw new Error("Invalid email or password")

  const ok = await bcrypt.compare(input.password, user.passwordHash)
  if (!ok) throw new Error("Invalid email or password")

  await createSessionForUser(user.id)

  return { user: { id: user.id, email: user.email, name: user.name } }
}

/**
 * Sign out by clearing cookie and deleting the session row (best effort).
 */
export async function signOut() {
  const token = (await cookies()).get(SESSION_COOKIE)?.value
  if (token) {
    const tokenHash = sha256(token)
    await prisma.session.delete({ where: { tokenHash } }).catch(() => {})
  }

  (await cookies()).set(SESSION_COOKIE, "", { ...cookieOptions(), maxAge: 0 })
}

async function createSessionForUser(userId: string) {
  const rawToken = newSessionToken()
  const tokenHash = sha256(rawToken)

  const h = headers()
  const userAgent = (await h).get("user-agent")
  // Next.js doesn't reliably provide IP in all deployments; optional
  const ip = (await h).get("x-forwarded-for")?.split(",")[0]?.trim() ?? null

  const expiresAt = addDays(now(), SESSION_DAYS)

  await prisma.session.create({
    data: {
      userId,
      tokenHash,
      expiresAt,
      userAgent,
      ip,
    },
  }); 
  
  (await cookies()).set(SESSION_COOKIE, rawToken, {
    ...cookieOptions(),
    expires: expiresAt,
  })
}


export function json(data: any, init?: ResponseInit) {
  return NextResponse.json(data, init)
}