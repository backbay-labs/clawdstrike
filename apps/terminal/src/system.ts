import { constants } from "node:fs"
import { access, stat } from "node:fs/promises"
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

async function isExecutable(path: string): Promise<boolean> {
  try {
    if (!(await stat(path)).isFile()) {
      return false
    }
    await access(path, constants.X_OK)
    return true
  } catch {
    return false
  }
}

export async function resolveCommandPath(command: string): Promise<string | null> {
  if (!command) {
    return null
  }

  if (command.includes("/") || command.includes("\\")) {
    return (await isExecutable(command)) ? command : null
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
      if (await isExecutable(resolved)) {
        return resolved
      }
    }
  }

  return null
}

export async function commandExists(command: string): Promise<boolean> {
  return (await resolveCommandPath(command)) !== null
}

export function homeDirFromEnv(): string | null {
  return process.env.HOME ?? process.env.USERPROFILE ?? null
}
