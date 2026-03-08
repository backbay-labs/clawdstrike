import { accessSync, constants } from "node:fs"
import { delimiter, join } from "node:path"

function executableCandidates(command: string): string[] {
  if (process.platform !== "win32") {
    return [command]
  }

  if (/\.[^/\\]+$/.test(command)) {
    return [command]
  }

  const pathext = (process.env.PATHEXT || ".EXE;.CMD;.BAT;.COM")
    .split(";")
    .filter(Boolean)

  return [command, ...pathext.map((ext) => `${command}${ext.toLowerCase()}`)]
}

function isExecutable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK)
    return true
  } catch {
    return false
  }
}

export function resolveCommandPath(command: string): string | null {
  if (!command) {
    return null
  }

  if (command.includes("/") || command.includes("\\")) {
    return isExecutable(command) ? command : null
  }

  const pathValue = process.env.PATH
  if (!pathValue) {
    return null
  }

  for (const directory of pathValue.split(delimiter)) {
    if (!directory) {
      continue
    }
    for (const candidate of executableCandidates(command)) {
      const resolved = join(directory, candidate)
      if (isExecutable(resolved)) {
        return resolved
      }
    }
  }

  return null
}

export function commandExists(command: string): boolean {
  return resolveCommandPath(command) !== null
}

export function homeDirFromEnv(): string | null {
  return process.env.HOME ?? process.env.USERPROFILE ?? null
}
