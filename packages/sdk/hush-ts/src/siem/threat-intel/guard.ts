import type { Guard, GuardAction, GuardContext } from "../../guards/types";
import { GuardResult, Severity } from "../../guards/types";
import { sha256, toHex } from "../../crypto/hash";
import type { ThreatIntelClient } from "./client";

export interface ThreatIntelGuardConfig {
  blockEgress?: boolean;
  blockFileNames?: boolean;
  blockFileHashes?: boolean;
}

export class ThreatIntelGuard implements Guard {
  readonly name = "threat_intel";

  private readonly cfg: Required<ThreatIntelGuardConfig>;

  constructor(
    private readonly intel: ThreatIntelClient,
    config: ThreatIntelGuardConfig = {}
  ) {
    this.cfg = {
      blockEgress: config.blockEgress ?? true,
      blockFileNames: config.blockFileNames ?? false,
      blockFileHashes: config.blockFileHashes ?? false,
    };
  }

  handles(action: GuardAction): boolean {
    if (this.cfg.blockEgress && action.actionType === "network_egress") {
      return true;
    }
    if (this.cfg.blockFileNames && (action.actionType === "file_access" || action.actionType === "file_write")) {
      return true;
    }
    if (this.cfg.blockFileHashes && action.actionType === "file_write") {
      return true;
    }
    return false;
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    if (this.cfg.blockEgress && action.actionType === "network_egress") {
      const host = action.host ?? "";
      if (!host.trim()) {
        return GuardResult.allow(this.name);
      }
      const blocked =
        isIp(host) ? this.intel.isIpBlocked(host) : this.intel.isDomainBlocked(host);
      if (blocked) {
        return GuardResult.block(this.name, Severity.ERROR, `Egress to ${host} blocked by threat intelligence`).withDetails({
          host,
          port: action.port,
          source: "stix/taxii",
        });
      }
      return GuardResult.allow(this.name);
    }

    if ((action.actionType === "file_access" || action.actionType === "file_write") && action.path) {
      const base = action.path.split("/").pop() ?? action.path;
      if (this.cfg.blockFileNames && this.intel.cache.isFileNameBlocked(base)) {
        return GuardResult.block(this.name, Severity.ERROR, `File access to ${action.path} blocked by threat intelligence`).withDetails({
          path: action.path,
          file_name: base,
          source: "stix/taxii",
        });
      }
    }

    if (action.actionType === "file_write" && action.content && this.cfg.blockFileHashes) {
      const hash = toHex(sha256(action.content));
      if (this.intel.cache.isFileHashBlocked(hash)) {
        return GuardResult.block(this.name, Severity.CRITICAL, `File write blocked by threat intelligence (sha256=${hash})`).withDetails({
          path: action.path,
          sha256: hash,
          source: "stix/taxii",
        });
      }
    }

    return GuardResult.allow(this.name);
  }
}

function isIp(host: string): boolean {
  return /^[0-9a-fA-F:.]+$/.test(host);
}

