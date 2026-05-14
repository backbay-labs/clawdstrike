import Link from 'next/link';
import { Menu } from 'lucide-react';
import { getAllTracks } from '@/lib/content';
import { LearningProgressBar } from '@/components/layout/learning-progress-bar';
import { Sidebar } from '@/components/layout/sidebar';
import { ClientShell } from '@/components/layout/client-shell';
import { ThemeToggle } from '@/components/layout/theme-toggle';
import {
  Sheet,
  SheetContent,
  SheetTrigger,
  SheetTitle,
} from '@/components/ui/sheet';

export default function TracksLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const tracks = getAllTracks();

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-40 border-b border-border-subtle bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="flex items-center justify-between px-6 py-3">
          <div className="flex min-w-0 flex-1 items-center gap-3">
            {/* Mobile sidebar trigger */}
            <Sheet>
              <SheetTrigger className="md:hidden -ml-2 rounded-md p-2 hover:bg-accent">
                <Menu className="h-5 w-5" />
                <span className="sr-only">Toggle sidebar</span>
              </SheetTrigger>
              <SheetContent side="left" className="w-72 p-0">
                <SheetTitle className="sr-only">Navigation</SheetTitle>
                <div className="pt-12">
                  <Sidebar tracks={tracks} />
                </div>
              </SheetContent>
            </Sheet>
            <Link
              href="/"
              className="shrink-0 font-display text-lg font-light tracking-tight text-foreground transition-colors hover:opacity-80"
            >
              ClawdStrike Academy
            </Link>
            <div className="mx-4 hidden min-w-0 flex-1 justify-center md:flex">
              <LearningProgressBar tracks={tracks} variant="compact" />
            </div>
          </div>
          <ThemeToggle />
        </div>
        <div className="border-t border-border-subtle px-6 py-2.5 md:hidden">
          <LearningProgressBar tracks={tracks} variant="compact" />
        </div>
      </header>

      <ClientShell tracks={tracks} />

      <div className="flex">
        {/* Desktop sidebar */}
        <aside className="hidden md:block w-72 shrink-0 border-r sticky top-[53px] h-[calc(100vh-53px)] overflow-hidden">
          <Sidebar tracks={tracks} />
        </aside>

        {/* Main content — wide readable column; prose max-w removed so grids fill horizontal space */}
        <main className="flex-1 min-w-0">
          <div
            className="mx-auto w-full max-w-[min(100%,88rem)] px-6 py-10 sm:px-8 lg:px-10 xl:px-12 prose prose-neutral max-w-none dark:prose-invert prose-headings:font-display prose-headings:font-light prose-h1:text-3xl prose-h1:tracking-tight prose-h2:text-2xl prose-h2:tracking-tight prose-a:text-primary prose-pre:bg-transparent prose-pre:p-0 prose-pre:m-0"
          >
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
