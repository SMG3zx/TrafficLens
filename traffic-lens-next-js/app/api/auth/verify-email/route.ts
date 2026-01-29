import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { TokenSchema } from "@/lib/validators";
import { sha256 } from "@/lib/crypto";

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const parsed = TokenSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "Invalid input" }, { status: 400 });

  const tokenHash = sha256(parsed.data.token);

  const user = await prisma.user.findFirst({
    where: {
      emailVerifyHash: tokenHash,
      emailVerifyExpires: { gt: new Date() },
    },
  });

  if (!user) return NextResponse.json({ error: "Invalid or expired token" }, { status: 400 });

  await prisma.user.update({
    where: { id: user.id },
    data: {
      emailVerifiedAt: new Date(),
      emailVerifyHash: null,
      emailVerifyExpires: null,
    },
  });

  return NextResponse.json({ ok: true });
}
