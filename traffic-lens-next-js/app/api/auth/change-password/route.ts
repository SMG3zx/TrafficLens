import { NextResponse } from "next/server";
import { ChangePasswordSchema } from "@/lib/validators";
import { requireUser } from "@/lib/auth";
import { verifyPassword, hashPassword } from "@/lib/password";
import { prisma } from "@/db/client";
import { clearAuthCookies } from "@/lib/cookies";

export async function POST(req: Request) {
  const user = await requireUser().catch(() => null);
  if (!user)
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json().catch(() => ({}));
  const parsed = ChangePasswordSchema.safeParse(body);
  if (!parsed.success)
    return NextResponse.json({ error: "Invalid input" }, { status: 400 });

  const ok = await verifyPassword(
    parsed.data.currentPassword,
    user.passwordHash,
  );
  if (!ok)
    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });

  await prisma.user.update({
    where: { id: user.id },
    data: { passwordHash: await hashPassword(parsed.data.newPassword) },
  });

  // optional: force re-login for this browser
  clearAuthCookies();
  return NextResponse.json({ ok: true });
}
