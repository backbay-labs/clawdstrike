
export interface FieldMappingEntry {
  /** Sigma canonical field name (e.g. "CommandLine"). */
  sigmaField: string;
  /** Splunk CIM equivalent (e.g. "process"). */
  splunkCIM?: string;
  /** Microsoft Sentinel equivalent (e.g. "CommandLine"). */
  sentinelField?: string;
  /** Elastic Common Schema equivalent (e.g. "process.command_line"). */
  ecsField?: string;
  /** Google UDM path equivalent (e.g. "target.process.command_line"). */
  udmPath?: string;
  /** Category for grouping in UI (e.g. "process", "file", "network", "dns", "registry", "authentication"). */
  category: string;
}

/** Platform target key for field translation. */
export type FieldMappingTarget = "splunkCIM" | "sentinelField" | "ecsField" | "udmPath";


/**
 * 50+ built-in field mapping entries covering the most common detection
 * scenarios across six categories: process, file, network, DNS, registry,
 * and authentication.
 *
 * Sources: Sigma taxonomy, Splunk CIM data model, Sentinel CommonSecurityLog /
 * SecurityEvent schemas, Elastic ECS 8.x, Google Chronicle UDM v2.
 *
 * Entries marked with `@confidence approximate` have best-effort mappings
 * that may vary across SIEM versions or deployments.
 */
export const BUILTIN_FIELD_MAPPINGS: FieldMappingEntry[] = [
  {
    sigmaField: "CommandLine",
    splunkCIM: "process",
    sentinelField: "CommandLine",
    ecsField: "process.command_line",
    udmPath: "target.process.command_line",
    category: "process",
  },
  {
    sigmaField: "Image",
    splunkCIM: "process_path",
    sentinelField: "NewProcessName",
    ecsField: "process.executable",
    udmPath: "target.process.file.full_path",
    category: "process",
  },
  {
    sigmaField: "ParentImage",
    splunkCIM: "parent_process_path",
    sentinelField: "ParentProcessName",
    ecsField: "process.parent.executable",
    udmPath: "principal.process.file.full_path",
    category: "process",
  },
  {
    sigmaField: "ParentCommandLine",
    splunkCIM: "parent_process",
    sentinelField: "ParentCommandLine",
    ecsField: "process.parent.command_line",
    udmPath: "principal.process.command_line",
    category: "process",
  },
  {
    sigmaField: "User",
    splunkCIM: "user",
    sentinelField: "SubjectUserName",
    ecsField: "user.name",
    udmPath: "principal.user.userid",
    category: "process",
  },
  {
    sigmaField: "IntegrityLevel",
    splunkCIM: "process_integrity_level",
    sentinelField: "IntegrityLevel",
    ecsField: "winlog.event_data.IntegrityLevel",
    /** @confidence approximate */
    udmPath: "target.process.integrity_level_rid",
    category: "process",
  },
  {
    sigmaField: "ProcessId",
    splunkCIM: "process_id",
    sentinelField: "NewProcessId",
    ecsField: "process.pid",
    udmPath: "target.process.pid",
    category: "process",
  },
  {
    sigmaField: "ParentProcessId",
    splunkCIM: "parent_process_id",
    sentinelField: "ProcessId",
    ecsField: "process.parent.pid",
    udmPath: "principal.process.pid",
    category: "process",
  },
  {
    sigmaField: "CurrentDirectory",
    splunkCIM: "process_current_directory",
    sentinelField: "CurrentDirectory",
    ecsField: "process.working_directory",
    udmPath: "target.process.file.full_path",
    category: "process",
  },
  {
    sigmaField: "OriginalFileName",
    splunkCIM: "original_file_name",
    sentinelField: "OriginalFileName",
    ecsField: "process.pe.original_file_name",
    /** @confidence approximate */
    udmPath: "target.process.file.pe_file.original_filename",
    category: "process",
  },
  {
    sigmaField: "Product",
    splunkCIM: "product",
    sentinelField: "Product",
    ecsField: "process.pe.product",
    /** @confidence approximate */
    udmPath: "target.process.file.pe_file.product",
    category: "process",
  },
  {
    sigmaField: "Company",
    splunkCIM: "vendor_product",
    sentinelField: "Company",
    ecsField: "process.pe.company",
    /** @confidence approximate */
    udmPath: "target.process.file.pe_file.company",
    category: "process",
  },
  {
    sigmaField: "Description",
    splunkCIM: "process_description",
    sentinelField: "Description",
    ecsField: "process.pe.description",
    /** @confidence approximate */
    udmPath: "target.process.file.pe_file.description",
    category: "process",
  },
  {
    sigmaField: "Hashes",
    splunkCIM: "process_hash",
    sentinelField: "Hashes",
    ecsField: "process.hash.md5",
    udmPath: "target.process.file.md5",
    category: "process",
  },
  {
    sigmaField: "LogonId",
    splunkCIM: "logon_id",
    sentinelField: "SubjectLogonId",
    ecsField: "winlog.logon.id",
    /** @confidence approximate */
    udmPath: "extensions.auth.mechanism",
    category: "process",
  },

  {
    sigmaField: "TargetFilename",
    splunkCIM: "file_path",
    sentinelField: "TargetFilename",
    ecsField: "file.path",
    udmPath: "target.file.full_path",
    category: "file",
  },
  {
    sigmaField: "SourceFilename",
    /** @confidence approximate */
    splunkCIM: "file_name",
    sentinelField: "SourceFilename",
    ecsField: "file.name",
    /** @confidence approximate */
    udmPath: "src.file.full_path",
    category: "file",
  },
  {
    sigmaField: "CreationUtcTime",
    splunkCIM: "file_create_time",
    sentinelField: "CreationUtcTime",
    ecsField: "file.created",
    /** @confidence approximate */
    udmPath: "target.file.create_time",
    category: "file",
  },
  {
    sigmaField: "Contents",
    /** @confidence approximate */
    splunkCIM: "file_content",
    /** @confidence approximate */
    sentinelField: "FileContent",
    /** @confidence approximate */
    ecsField: "file.content",
    /** @confidence approximate */
    udmPath: "target.file.content",
    category: "file",
  },
  {
    sigmaField: "FilePath",
    splunkCIM: "file_path",
    sentinelField: "FilePath",
    ecsField: "file.path",
    udmPath: "target.file.full_path",
    category: "file",
  },
  {
    sigmaField: "FileExtension",
    /** @confidence approximate */
    splunkCIM: "file_extension",
    /** @confidence approximate */
    sentinelField: "FileExtension",
    ecsField: "file.extension",
    /** @confidence approximate */
    udmPath: "target.file.mime_type",
    category: "file",
  },
  {
    sigmaField: "FileSize",
    splunkCIM: "file_size",
    /** @confidence approximate */
    sentinelField: "FileSize",
    ecsField: "file.size",
    /** @confidence approximate */
    udmPath: "target.file.size",
    category: "file",
  },
  {
    sigmaField: "FileOwner",
    splunkCIM: "file_owner",
    /** @confidence approximate */
    sentinelField: "FileOwner",
    ecsField: "file.owner",
    /** @confidence approximate */
    udmPath: "target.file.owner",
    category: "file",
  },

  {
    sigmaField: "SourceIp",
    splunkCIM: "src_ip",
    sentinelField: "SourceIP",
    ecsField: "source.ip",
    udmPath: "principal.ip",
    category: "network",
  },
  {
    sigmaField: "DestinationIp",
    splunkCIM: "dest_ip",
    sentinelField: "DestinationIP",
    ecsField: "destination.ip",
    udmPath: "target.ip",
    category: "network",
  },
  {
    sigmaField: "SourcePort",
    splunkCIM: "src_port",
    sentinelField: "SourcePort",
    ecsField: "source.port",
    udmPath: "principal.port",
    category: "network",
  },
  {
    sigmaField: "DestinationPort",
    splunkCIM: "dest_port",
    sentinelField: "DestinationPort",
    ecsField: "destination.port",
    udmPath: "target.port",
    category: "network",
  },
  {
    sigmaField: "Protocol",
    splunkCIM: "transport",
    sentinelField: "Protocol",
    ecsField: "network.transport",
    udmPath: "network.ip_protocol",
    category: "network",
  },
  {
    sigmaField: "DestinationHostname",
    splunkCIM: "dest",
    sentinelField: "DestinationHostname",
    ecsField: "destination.domain",
    udmPath: "target.hostname",
    category: "network",
  },
  {
    sigmaField: "SourceHostname",
    splunkCIM: "src",
    sentinelField: "SourceHostname",
    ecsField: "source.domain",
    /** @confidence approximate */
    udmPath: "principal.hostname",
    category: "network",
  },
  {
    sigmaField: "Initiated",
    /** @confidence approximate */
    splunkCIM: "direction",
    sentinelField: "Initiated",
    ecsField: "network.direction",
    /** @confidence approximate */
    udmPath: "network.direction",
    category: "network",
  },
  {
    sigmaField: "DestinationIsIpv6",
    /** @confidence approximate */
    splunkCIM: "dest_ip_version",
    /** @confidence approximate */
    sentinelField: "DestinationIsIpv6",
    /** @confidence approximate */
    ecsField: "network.type",
    /** @confidence approximate */
    udmPath: "target.ip_version",
    category: "network",
  },
  {
    sigmaField: "DestinationPortName",
    splunkCIM: "dest_port_name",
    /** @confidence approximate */
    sentinelField: "DestinationPortName",
    ecsField: "destination.port_name",
    /** @confidence approximate */
    udmPath: "target.port_name",
    category: "network",
  },

  {
    sigmaField: "QueryName",
    splunkCIM: "query",
    sentinelField: "QueryName",
    ecsField: "dns.question.name",
    udmPath: "network.dns.questions.name",
    category: "dns",
  },
  {
    sigmaField: "QueryType",
    splunkCIM: "query_type",
    sentinelField: "QueryType",
    ecsField: "dns.question.type",
    udmPath: "network.dns.questions.type",
    category: "dns",
  },
  {
    sigmaField: "QueryStatus",
    /** @confidence approximate */
    splunkCIM: "reply_code",
    sentinelField: "QueryStatus",
    ecsField: "dns.response_code",
    /** @confidence approximate */
    udmPath: "network.dns.response_code",
    category: "dns",
  },
  {
    sigmaField: "QueryResults",
    /** @confidence approximate */
    splunkCIM: "answer",
    sentinelField: "QueryResults",
    ecsField: "dns.answers.data",
    /** @confidence approximate */
    udmPath: "network.dns.answers.data",
    category: "dns",
  },
  {
    sigmaField: "record_type",
    splunkCIM: "record_type",
    /** @confidence approximate */
    sentinelField: "QueryType",
    ecsField: "dns.question.type",
    /** @confidence approximate */
    udmPath: "network.dns.questions.type",
    category: "dns",
  },

  {
    sigmaField: "TargetObject",
    splunkCIM: "registry_path",
    sentinelField: "TargetObject",
    ecsField: "registry.path",
    udmPath: "target.registry.registry_key",
    category: "registry",
  },
  {
    sigmaField: "Details",
    splunkCIM: "registry_value_data",
    sentinelField: "Details",
    ecsField: "registry.data.strings",
    /** @confidence approximate */
    udmPath: "target.registry.registry_value_data",
    category: "registry",
  },
  {
    sigmaField: "EventType",
    splunkCIM: "action",
    sentinelField: "EventType",
    ecsField: "event.action",
    udmPath: "metadata.event_type",
    category: "registry",
  },
  {
    sigmaField: "NewValue",
    /** @confidence approximate */
    splunkCIM: "registry_value_data",
    /** @confidence approximate */
    sentinelField: "NewValue",
    /** @confidence approximate */
    ecsField: "registry.data.strings",
    /** @confidence approximate */
    udmPath: "target.registry.registry_value_data",
    category: "registry",
  },
  {
    sigmaField: "OldValue",
    /** @confidence approximate */
    splunkCIM: "registry_value_data_old",
    /** @confidence approximate */
    sentinelField: "PreviousValue",
    /** @confidence approximate */
    ecsField: "registry.data.strings",
    /** @confidence approximate */
    udmPath: "target.registry.registry_value_data",
    category: "registry",
  },

  {
    sigmaField: "LogonType",
    splunkCIM: "logon_type",
    sentinelField: "LogonType",
    ecsField: "winlog.logon.type",
    /** @confidence approximate */
    udmPath: "extensions.auth.type",
    category: "authentication",
  },
  {
    sigmaField: "AuthenticationPackageName",
    /** @confidence approximate */
    splunkCIM: "authentication_method",
    sentinelField: "AuthenticationPackageName",
    ecsField: "winlog.event_data.AuthenticationPackageName",
    /** @confidence approximate */
    udmPath: "extensions.auth.mechanism",
    category: "authentication",
  },
  {
    sigmaField: "TargetUserName",
    splunkCIM: "user",
    sentinelField: "TargetUserName",
    ecsField: "user.target.name",
    udmPath: "target.user.userid",
    category: "authentication",
  },
  {
    sigmaField: "TargetDomainName",
    splunkCIM: "user_domain",
    sentinelField: "TargetDomainName",
    ecsField: "user.target.domain",
    /** @confidence approximate */
    udmPath: "target.user.group_identifiers",
    category: "authentication",
  },
  {
    sigmaField: "SourceWorkstation",
    /** @confidence approximate */
    splunkCIM: "src",
    sentinelField: "WorkstationName",
    ecsField: "source.domain",
    /** @confidence approximate */
    udmPath: "principal.hostname",
    category: "authentication",
  },
  {
    sigmaField: "IpAddress",
    splunkCIM: "src_ip",
    sentinelField: "IpAddress",
    ecsField: "source.ip",
    udmPath: "principal.ip",
    category: "authentication",
  },
  {
    sigmaField: "SubjectUserName",
    /** @confidence approximate */
    splunkCIM: "src_user",
    sentinelField: "SubjectUserName",
    ecsField: "user.name",
    udmPath: "principal.user.userid",
    category: "authentication",
  },
];


/** Module-level map keyed by sigmaField for O(1) lookups. */
const fieldMap = new Map<string, FieldMappingEntry>();

/** Populate the map from built-in entries at module load. */
for (const entry of BUILTIN_FIELD_MAPPINGS) {
  fieldMap.set(entry.sigmaField, entry);
}


/**
 * Register additional field mappings (e.g. from plugins).
 *
 * If a `sigmaField` already exists, the new entry is MERGED into the
 * existing one -- undefined platform fields are filled in without
 * overwriting existing values. This allows plugins to extend mappings
 * (e.g. a Sumo Logic plugin adding sumo-specific fields to existing entries).
 *
 * @returns A dispose function that removes the added/merged entries,
 *          restoring previous values where applicable.
 */
export function registerFieldMappings(entries: FieldMappingEntry[]): () => void {
  /** Snapshot of previous state for each affected key, used to undo on dispose. */
  const previousState = new Map<string, FieldMappingEntry | undefined>();

  for (const entry of entries) {
    const existing = fieldMap.get(entry.sigmaField);
    previousState.set(entry.sigmaField, existing ? { ...existing } : undefined);

    if (existing) {
      // Merge: fill in undefined platform fields without overwriting.
      if (entry.splunkCIM !== undefined && existing.splunkCIM === undefined) {
        existing.splunkCIM = entry.splunkCIM;
      }
      if (entry.sentinelField !== undefined && existing.sentinelField === undefined) {
        existing.sentinelField = entry.sentinelField;
      }
      if (entry.ecsField !== undefined && existing.ecsField === undefined) {
        existing.ecsField = entry.ecsField;
      }
      if (entry.udmPath !== undefined && existing.udmPath === undefined) {
        existing.udmPath = entry.udmPath;
      }
    } else {
      fieldMap.set(entry.sigmaField, { ...entry });
    }
  }

  return () => {
    for (const [key, prev] of previousState) {
      if (prev === undefined) {
        fieldMap.delete(key);
      } else {
        fieldMap.set(key, prev);
      }
    }
  };
}

/**
 * Look up a single field mapping by its Sigma canonical name.
 *
 * @returns The mapping entry or `null` if not found.
 */
export function getFieldMapping(sigmaField: string): FieldMappingEntry | null {
  return fieldMap.get(sigmaField) ?? null;
}

/**
 * Convenience function: translate a Sigma field name to its equivalent in a
 * specific target platform.
 *
 * @returns The mapped field name string, or `null` if unmapped.
 */
export function translateField(
  sigmaField: string,
  targetFormat: FieldMappingTarget,
): string | null {
  const entry = fieldMap.get(sigmaField);
  if (!entry) return null;
  return entry[targetFormat] ?? null;
}

/**
 * Return all currently registered field mapping entries.
 *
 * Includes both built-in and plugin-registered entries.
 */
export function getAllFieldMappings(): FieldMappingEntry[] {
  return Array.from(fieldMap.values());
}

/**
 * Return field mapping entries filtered by category.
 *
 * @param category  One of "process", "file", "network", "dns", "registry", "authentication", or a custom category.
 */
export function getFieldMappingsByCategory(category: string): FieldMappingEntry[] {
  return Array.from(fieldMap.values()).filter((e) => e.category === category);
}
