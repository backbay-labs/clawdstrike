export function commandExists(command: string): boolean {
  const bunRuntime = Bun as unknown as {
    which?: (binary: string) => string | null | undefined
  }

  return !!bunRuntime.which?.(command)
}

export function homeDirFromEnv(): string | null {
  return process.env.HOME ?? process.env.USERPROFILE ?? null
}
