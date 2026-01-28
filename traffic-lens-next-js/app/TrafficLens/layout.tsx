import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"

export default function AppLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const username = "username" // replace with session later

  return (
    <div className="flex h-dvh">
      <aside className="w-[260px] bg-slate-950 text-white p-4">
        <h2 className="text-[18px] font-semibold mb-4">TrafficLens</h2>

        <nav className="space-y-1">
          <Link
            href="/"
            className="block rounded-lg px-3 py-2 text-slate-300 hover:bg-white/10 hover:text-white"
          >
            Dashboard
          </Link>
          <Link
            href="/uploads"
            className="block rounded-lg px-3 py-2 text-slate-300 hover:bg-white/10 hover:text-white"
          >
            PCAP Uploads
          </Link>
          <Link
            href="/analysis"
            className="block rounded-lg px-3 py-2 text-slate-300 hover:bg-white/10 hover:text-white"
          >
            Analysis
          </Link>
          <Link
            href="/settings"
            className="block rounded-lg px-3 py-2 text-slate-300 hover:bg-white/10 hover:text-white"
          >
            Settings
          </Link>
        </nav>

        <Separator className="my-4 bg-white/10" />

        <form action="/api/logout" method="post">
          <Button type="submit" className="w-full">
            Logout
          </Button>
        </form>

        <p className="mt-3 text-sm text-slate-400">
          Logged in as {username}
        </p>
      </aside>

      <main className="flex-1 overflow-auto bg-slate-950/80 text-white p-6">
        {children}
      </main>
    </div>
  )
}