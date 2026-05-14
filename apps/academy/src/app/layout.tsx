import type { Metadata } from 'next';
import { Cormorant_Garamond, Inter, JetBrains_Mono } from 'next/font/google';
import { ThemeProvider } from '@/providers/theme-provider';
import './globals.css';

const inter = Inter({
  variable: '--font-inter',
  subsets: ['latin'],
  display: 'swap',
});

/**
 * Display headings: DESIGN.md references Waldenburg 300; we use Cormorant Garamond
 * 300 as a licensed, Google-hosted whisper-light substitute.
 */
const cormorantDisplay = Cormorant_Garamond({
  variable: '--font-academy-display',
  subsets: ['latin'],
  weight: ['300', '600'],
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  variable: '--font-jetbrains-mono',
  subsets: ['latin'],
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'ClawdStrike Academy',
  description:
    'Interactive onboarding for the ClawdStrike runtime security system',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      {/* suppressHydrationWarning: extensions (e.g. Grammarly) inject data-* attrs on <body> before hydration */}
      <body
        suppressHydrationWarning
        className={`${inter.variable} ${cormorantDisplay.variable} ${jetbrainsMono.variable} font-sans antialiased [font-feature-settings:'liga'_1] tracking-[0.01em]`}
      >
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  );
}
