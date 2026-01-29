import { NextResponse } from "next/server";
import { prisma } from "@/db/client";
import { ResetSchema } from "@/lib/validators";
import { sha256 } from "@/lib/crypto";
import { hashPassword } from "@/lib/password";
import { clearAuthCookies } from "@/lib/cookies";

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const parsed = ResetSchema.safeParse(body);
  if (!parsed.success)
    return NextResponse.json({ error: "Invalid input" }, { status: 400 });

  const tokenHash = sha256(parsed.data.token);

  const user = await prisma.user.findFirst({
    where: {
      resetHash: tokenHash,
      resetExpires: { gt: new Date() },
    },
  });

  if (!user)
    return NextResponse.json(
      { error: "Invalid or expired token" },
      { status: 400 },
    );

  const passwordHash = await hashPassword(parsed.data.newPassword);

  await prisma.user.update({
    where: { id: user.id },
    data: {
      passwordHash,
      resetHash: null,
      resetExpires: null,
    },
  });

  // clears cookies for this browser only
  clearAuthCookies();
  return NextResponse.json({ ok: true });
}
