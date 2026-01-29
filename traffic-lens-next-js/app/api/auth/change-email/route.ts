import { NextResponse } from "next/server";
import { ChangeEmailSchema } from "@/lib/validators";
import { requireUser } from "@/lib/auth";
import { verifyPassword } from "@/lib/password";
import { prisma } from "@/lib/prisma";
import { randomToken, sha256 } from "@/lib/crypto";
import { sendMail } from "@/lib/mailer";

export async function POST(req: Request) {
  const user = await requireUser().catch(() => null);
  if (!user)
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json().catch(() => ({}));
  const parsed = ChangeEmailSchema.safeParse(body);
  if (!parsed.success)
    return NextResponse.json({ error: "Invalid input" }, { status: 400 });

  const ok = await verifyPassword(
    parsed.data.currentPassword,
    user.passwordHash,
  );
  if (!ok)
    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });

  const newEmail = parsed.data.newEmail.toLowerCase();
  const taken = await prisma.user.findUnique({ where: { email: newEmail } });
  if (taken)
    return NextResponse.json(
      { error: "Email already in use" },
      { status: 409 },
    );

  const token = randomToken();
  const tokenHash = sha256(token);
  const expires = new Date(Date.now() + 1000 * 60 * 60); // 1h

  await prisma.user.update({
    where: { id: user.id },
    data: {
      pendingEmail: newEmail,
      emailChangeHash: tokenHash,
      emailChangeExpires: expires,
    },
  });

  const confirmUrl = `${process.env.APP_URL}/confirm-email-change?token=${token}`;

  await sendMail(
    newEmail,
    "Confirm your new email",
    `<p>Confirm email change:</p><p><a href="${confirmUrl}">${confirmUrl}</a></p>`,
  );

  return NextResponse.json({ ok: true });
}
