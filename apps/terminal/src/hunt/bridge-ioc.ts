// hunt/bridge-ioc.ts - IOC (Indicators of Compromise) bridge wrapper

import { runHuntCommand } from "./bridge"
import type { IocMatch } from "./types"

export interface IocOptions {
  feeds: string[]
  since?: string
  until?: string
}

export async function runIoc(opts: IocOptions): Promise<IocMatch[]> {
  const args = ["ioc"]
  for (const feed of opts.feeds) args.push("--feed", feed)
  if (opts.since) args.push("--since", opts.since)
  if (opts.until) args.push("--until", opts.until)
  const result = await runHuntCommand<IocMatch[]>(args)
  return result.data ?? []
}
