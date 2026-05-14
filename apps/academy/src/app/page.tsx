import Link from 'next/link';
import { BookOpen, ArrowRight } from 'lucide-react';
import { LearningProgressBar } from '@/components/layout/learning-progress-bar';
import { ThemeToggle } from '@/components/layout/theme-toggle';
import { Button } from '@/components/ui/button';
import { getAllTracks } from '@/lib/content';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardFooter,
} from '@/components/ui/card';

export default function Home() {
  const tracks = getAllTracks();
  const firstTrackLessons = tracks[0]?.lessons;
  const firstLessonPath =
    firstTrackLessons?.length ?
      [...firstTrackLessons].sort((a, b) => a.order - b.order)[0]!.path
    : '/tracks/guard-gallery';

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-20 flex items-center justify-between border-b border-border-subtle bg-background/85 px-6 py-4 backdrop-blur-md supports-[backdrop-filter]:bg-background/70">
        <h1 className="font-display text-2xl font-light tracking-tight text-foreground md:text-3xl">
          ClawdStrike Academy
        </h1>
        <ThemeToggle />
      </header>

      <main>
        <section className="mx-auto max-w-[min(100%,56rem)] px-6 pb-16 pt-14 sm:px-8 md:pt-20 lg:max-w-[min(100%,64rem)] lg:px-10">
          <p className="mb-4 text-[0.9375rem] font-medium tracking-[0.01em] text-warm-gray">
            Runtime security for AI agents
          </p>
          <h2 className="font-display text-[clamp(2.25rem,6vw,3rem)] font-light leading-[1.08] tracking-[-0.06rem] text-foreground">
            Learn runtime security
          </h2>
          <p className="mt-6 max-w-2xl text-lg font-normal leading-[1.6] tracking-[0.011em] text-muted-foreground">
            Interactive onboarding for the ClawdStrike enforcement system.
            Explore threat scenarios, dig into guards, and build policies — all
            backed by the real WASM engine in your browser.
          </p>
          <div className="mt-10 w-full max-w-md">
            <LearningProgressBar tracks={tracks} />
          </div>
          <div className="mt-10 flex flex-wrap items-center gap-3">
            <Button variant="warm" size="lg" asChild>
              <Link href={firstLessonPath}>Start learning</Link>
            </Button>
            <Button variant="outline" size="lg" asChild>
              <Link href="/tracks/guard-gallery">Guard gallery</Link>
            </Button>
          </div>
        </section>

        <section className="border-t border-border-subtle bg-surface-muted py-16 md:py-20">
          <div className="mx-auto max-w-[min(100%,88rem)] px-6 sm:px-8 lg:px-10 xl:px-12">
            <h3 className="font-display text-4xl font-light tracking-tight text-foreground md:text-[2.25rem] md:leading-[1.17]">
              Learning tracks
            </h3>
            <p className="mt-3 max-w-xl text-base tracking-[0.01em] text-muted-foreground">
              Pick a track and work through lessons in order — each ends with
              hands-on challenges.
            </p>

            <div className="mt-10 grid gap-6 sm:grid-cols-2">
              {tracks.map((track) => (
                <Link
                  key={track.slug}
                  href={track.lessons[0]?.path ?? `/tracks/${track.slug}`}
                  className="no-underline"
                >
                  <Card className="h-full cursor-pointer shadow-inset-edge hover:border-foreground/10 hover:shadow-eleven-card">
                    <CardHeader>
                      <div className="mb-2 flex items-center gap-2">
                        <BookOpen
                          className="h-5 w-5 text-foreground"
                          strokeWidth={1.25}
                        />
                        <span className="text-sm font-medium tracking-[0.01em] text-warm-gray">
                          {track.lessons.length}{' '}
                          {track.lessons.length === 1 ? 'lesson' : 'lessons'}
                        </span>
                      </div>
                      <CardTitle className="text-[2rem] leading-[1.13]">
                        {track.title}
                      </CardTitle>
                      <CardDescription>
                        {track.lessons.map((l) => l.title).join(' · ')}
                      </CardDescription>
                    </CardHeader>
                    <CardFooter>
                      <span className="flex items-center gap-1 text-[0.9375rem] font-medium text-foreground">
                        Open track
                        <ArrowRight className="h-4 w-4" strokeWidth={1.5} />
                      </span>
                    </CardFooter>
                  </Card>
                </Link>
              ))}
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
