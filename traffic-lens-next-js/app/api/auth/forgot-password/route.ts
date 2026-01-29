import { NextResponse } from "next/server";
import { prisma } from "@/db/client";
import { ForgotSchema } from "@/lib/validators";
import { randomToken, sha256 } from "@/lib/crypto";
import { sendMail } from "@/lib/mailer";

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const parsed = ForgotSchema.safeParse(body);
  if (!parsed.success)
    return NextResponse.json({ error: "Invalid input" }, { status: 400 });

  const email = parsed.data.email.toLowerCase();
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) return NextResponse.json({ ok: true });

  const token = randomToken();
  const tokenHash = sha256(token);
  const expires = new Date(Date.now() + 1000 * 60 * 30); // 30 min

  await prisma.user.update({
    where: { id: user.id },
    data: { resetHash: tokenHash, resetExpires: expires },
  });

  const resetUrl = `${process.env.APP_URL}/reset-password?token=${token}`;

  await sendMail(
    user.email,
    "Reset your password",
    `<p>Reset your password:</p><p><a href="${resetUrl}">${resetUrl}</a></p>`,
  );

  return NextResponse.json({ ok: true });
}
