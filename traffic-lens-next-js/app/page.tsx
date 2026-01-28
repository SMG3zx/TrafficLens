import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  NavigationMenu,
  NavigationMenuContent,
  NavigationMenuItem,
  NavigationMenuLink,
  NavigationMenuList,
  NavigationMenuTrigger,
} from "@/components/ui/navigation-menu";

function ProductMenu() {
  return (
    <NavigationMenu>
      <NavigationMenuList>
        <NavigationMenuItem>
          <NavigationMenuTrigger className="bg-transparent text-white/80 hover:text-white">
            Product
          </NavigationMenuTrigger>
          <NavigationMenuContent>
            <div className="w-[760px] p-4">
              <div className="grid grid-cols-2 gap-3">
                <MenuCard
                  title="Universal Gateway"
                  description="One gateway for all your traffic"
                />
                <MenuCard
                  title="Secure Tunnels"
                  description="Connect to services anywhere"
                />
                <MenuCard
                  title="AI Gateway"
                  description="One gateway for every AI model"
                  pill="Early access"
                />
                <MenuCard
                  title="Traffic Observability"
                  description="Observe in real time & export"
                />
                <MenuCard
                  title="Traffic Policy"
                  description="Route, transform, authenticate"
                />
                <MenuCard
                  title="Kubernetes Operator"
                  description="Ingress & Gateway API controller"
                />
              </div>
            </div>
          </NavigationMenuContent>
        </NavigationMenuItem>

        <TopNavLink href="/problems">Problems we solve</TopNavLink>
        <TopNavLink href="/resources">Resources</TopNavLink>
        <TopNavLink href="/docs">Docs</TopNavLink>
        <TopNavLink href="/blog">Blog</TopNavLink>
        <TopNavLink href="/download">Download</TopNavLink>
      </NavigationMenuList>
    </NavigationMenu>
  );
}

function TopNavLink({
  href,
  children,
}: {
  href: string;
  children: React.ReactNode;
}) {
  return (
    <NavigationMenuItem>
      <NavigationMenuLink asChild>
        <Link
          href={href}
          className="px-3 py-2 text-sm font-medium text-white/70 hover:text-white"
        >
          {children}
        </Link>
      </NavigationMenuLink>
    </NavigationMenuItem>
  );
}

function MenuCard({
  title,
  description,
  pill,
}: {
  title: string;
  description: string;
  pill?: string;
}) {
  return (
    <a
      href="#"
      className="group rounded-xl border border-white/10 bg-white/5 p-4 hover:bg-white/10"
    >
      <div className="flex items-center gap-2">
        <div className="text-sm font-semibold text-white">{title}</div>
        {pill ? (
          <span className="rounded-full border border-white/15 bg-white/10 px-2 py-0.5 text-[10px] uppercase tracking-wide text-white/80">
            {pill}
          </span>
        ) : null}
      </div>
      <div className="mt-1 text-sm text-white/60">{description}</div>
    </a>
  );
}

export default function HomePage() {
  return (
    <div className="min-h-dvh bg-black text-white">
      {/* background glow (structure only) */}
      <div className="pointer-events-none fixed inset-0">
        <div className="absolute left-1/2 top-[28%] h-[520px] w-[900px] -translate-x-1/2 rounded-full bg-white/10 blur-3xl" />
        <div className="absolute left-1/2 top-[32%] h-[320px] w-[560px] -translate-x-1/2 rounded-full bg-white/10 blur-2xl" />
      </div>

      {/* header */}
      <header className="relative z-10 mx-auto flex w-full max-w-6xl items-center justify-between px-6 py-5">
        <Link href="/" className="text-2xl font-semibold tracking-tight">
          TrafficLens
        </Link>

        <div className="hidden items-center gap-6 md:flex">
          <ProductMenu />
        </div>

        <div className="flex items-center gap-2">
          <Link href={"/login"}>
            <Button variant="ghost" className="text-white/80 hover:text-white">
              Log in
            </Button>
          </Link>
          <Link href={"/signup"}>
            <Button className="rounded-full">Sign up</Button>
          </Link>
        </div>
      </header>

      <Separator className="relative z-10 mx-auto w-full max-w-6xl bg-white/10" />

      {/* hero */}
      <main className="relative z-10 mx-auto flex w-full max-w-6xl flex-col items-center px-6 pb-20 pt-16 text-center">
        <h1 className="max-w-3xl text-5xl font-semibold leading-[1.05] tracking-tight md:text-6xl">
          All your traffic.
          <br />
          <span className="text-white/80">One lens.</span>
        </h1>

        <p className="mt-6 max-w-2xl text-lg text-white/65">
          A simple headline paragraph that explains what your product does and
          why it matters. Keep it short and scannable.
        </p>

        <div className="mt-10 flex flex-col items-center gap-3 sm:flex-row">
          <Button size="lg" className="rounded-full px-8">
            Start building
          </Button>
          <Button
            size="lg"
            variant="secondary"
            className="rounded-full bg-white/10 text-white hover:bg-white/15 px-8"
          >
            Read the docs
          </Button>
        </div>

        {/* optional: a “below-the-fold” placeholder */}
        <div className="mt-16 w-full max-w-4xl rounded-2xl border border-white/10 bg-white/5 p-6 text-left">
          <div className="text-sm font-medium text-white/80">Next section</div>
          <div className="mt-2 text-sm text-white/60">
            Put logos, quick bullets, or a simple “how it works” grid here.
          </div>
        </div>
      </main>
    </div>
  );
}
