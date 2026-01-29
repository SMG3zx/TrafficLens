import { NextResponse } from "next/server";
import { prisma } from "@/db/client";
import { TokenSchema } from "@/lib/validators";
import { sha256 } from "@/lib/crypto";
import { clearAuthCookies } from "@/lib/cookies";

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const parsed = TokenSchema.safeParse(body);
  if (!parsed.success)
    return NextResponse.json({ error: "Invalid input" }, { status: 400 });

  const tokenHash = sha256(parsed.data.token);

  const user = await prisma.user.findFirst({
    where: {
      emailChangeHash: tokenHash,
      emailChangeExpires: { gt: new Date() },
      pendingEmail: { not: null },
    },
  });

  if (!user || !user.pendingEmail) {
    return NextResponse.json(
      { error: "Invalid or expired token" },
      { status: 400 },
    );
  }

  const taken = await prisma.user.findUnique({
    where: { email: user.pendingEmail },
  });
  if (taken)
    return NextResponse.json(
      { error: "Email already in use" },
      { status: 409 },
    );

  await prisma.user.update({
    where: { id: user.id },
    data: {
      email: user.pendingEmail,
      pendingEmail: null,
      emailChangeHash: null,
      emailChangeExpires: null,
      emailVerifiedAt: new Date(), // optional; or keep prior state
    },
  });

  // clears cookies for this browser only (no global revoke in pure stateless)
  clearAuthCookies();
  return NextResponse.json({ ok: true });
}
