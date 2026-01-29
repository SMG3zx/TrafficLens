import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { SignupSchema } from "@/lib/validators";
import { hashPassword } from "@/lib/password";
import { randomToken, sha256 } from "@/lib/crypto";
import { sendMail } from "@/lib/mailer";

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const parsed = SignupSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "Invalid input" }, { status: 400 });

  const email = parsed.data.email.toLowerCase();
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) return NextResponse.json({ error: "Email already in use" }, { status: 409 });

  const passwordHash = await hashPassword(parsed.data.password);

  const token = randomToken();
  const tokenHash = sha256(token);
  const expires = new Date(Date.now() + 1000 * 60 * 60 * 24); // 24h

  const user = await prisma.user.create({
    data: {
      email,
      passwordHash,
      emailVerifyHash: tokenHash,
      emailVerifyExpires: expires,
    },
  });

  const verifyUrl = `${process.env.APP_URL}/verify-email?token=${token}`;

  await sendMail(
    user.email,
    "Verify your email",
    `<p>Verify your email:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p>`
  );

  return NextResponse.json({ ok: true });
}
