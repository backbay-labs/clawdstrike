import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useReducer,
  useRef,
  type ReactNode,
} from "react";
import {
  FINDING_ENVELOPE_SCHEMA,
  hashProtocolPayload,
  isFindingEnvelope,
  isHeadAnnouncement,
  isHubTrustPolicy,
  isProtocolDigest,
  isRevocationEnvelope,
  serializeProtocolPayload,
  type FindingEnvelope,
  type HeadAnnouncement,
  type HubTrustPolicy,
  type ProtocolDigest,
  type RevocationEnvelope,
} from "./swarm-protocol";
import {
  planSwarmReplay,
  summarizeSwarmReplayProgress,
  validateSwarmReplayBatch,
  type SwarmFeedSyncState,
  type SwarmReplayBatch,
  type SwarmReplayRequest,
  type SwarmReplayValidationResult,
} from "./swarm-sync";
import {
  DEFAULT_HUB_TRUST_POLICY,
  FAIL_CLOSED_HUB_TRUST_POLICY,
  evaluateFindingTrustPolicy,
  evaluateFindingTrustPolicySync,
  evaluateRevocationTrustPolicy,
  evaluateRevocationTrustPolicySync,
  type FindingTrustPolicyDecision,
  type FindingTrustPolicyRejectionReason,
} from "./swarm-trust-policy";

export const SWARM_FEED_STORAGE_KEY = "clawdstrike_workbench_swarm_feed";

type SwarmHeadLane = "findings" | "revocations";

const FINDING_HEAD_LANE: SwarmHeadLane = "findings";
const REVOCATION_HEAD_LANE: SwarmHeadLane = "revocations";

export interface SwarmFindingEnvelopeRecord {
  swarmId: string;
  envelope: FindingEnvelope;
  receivedAt: number;
  digest?: ProtocolDigest;
}

export interface SwarmHeadAnnouncementRecord {
  swarmId: string;
  lane: SwarmHeadLane;
  announcement: HeadAnnouncement;
  receivedAt: number;
}

export interface SwarmRevocationEnvelopeRecord {
  swarmId: string;
  envelope: RevocationEnvelope;
  receivedAt: number;
}

export type SwarmFindingReferenceResolution =
  | {
      status: "active";
      swarmId: string;
      feedId: string;
      findingId: string;
      envelope: FindingEnvelope;
    }
  | {
      status: "revoked";
      swarmId: string;
      feedId: string;
      findingId: string;
      envelope?: FindingEnvelope;
      revocation: RevocationEnvelope;
    }
  | {
      status: "superseded";
      swarmId: string;
      feedId: string;
      findingId: string;
      envelope?: FindingEnvelope;
      revocation: RevocationEnvelope;
      replacement: NonNullable<RevocationEnvelope["replacement"]> & {
        envelope?: FindingEnvelope;
      };
    };

export interface SwarmProjectedFindingRecord extends SwarmFindingEnvelopeRecord {
  sourceFindingIds: string[];
}

export interface SwarmFeedState {
  findingEnvelopes: SwarmFindingEnvelopeRecord[];
  headAnnouncements: SwarmHeadAnnouncementRecord[];
  revocationEnvelopes: SwarmRevocationEnvelopeRecord[];
  quarantinedFindingEnvelopes: SwarmFindingEnvelopeRecord[];
  quarantinedHeadAnnouncements: SwarmHeadAnnouncementRecord[];
  quarantinedRevocationEnvelopes: SwarmRevocationEnvelopeRecord[];
  defaultTrustPolicy: HubTrustPolicy;
  trustPolicies: Record<string, HubTrustPolicy>;
}

type MaybePromise<T> = T | Promise<T>;

type SwarmFeedAction =
  | { type: "INGEST_FINDING_ENVELOPE"; record: SwarmFindingEnvelopeRecord }
  | {
      type: "REMOVE_FINDING_ENVELOPE";
      swarmId: string;
      feedId: string;
      issuerId: string;
      findingId: string;
    }
  | { type: "INGEST_HEAD_ANNOUNCEMENT"; record: SwarmHeadAnnouncementRecord }
  | {
      type: "REMOVE_HEAD_ANNOUNCEMENT";
      swarmId: string;
      feedId: string;
      issuerId: string;
      lane?: SwarmHeadLane;
    }
  | { type: "INGEST_REVOCATION_ENVELOPE"; record: SwarmRevocationEnvelopeRecord }
  | { type: "SET_TRUST_POLICY"; swarmId: string; trustPolicy: HubTrustPolicy }
  | { type: "LOAD"; state: SwarmFeedState };

const INITIAL_SWARM_FEED_STATE: SwarmFeedState = {
  findingEnvelopes: [],
  headAnnouncements: [],
  revocationEnvelopes: [],
  quarantinedFindingEnvelopes: [],
  quarantinedHeadAnnouncements: [],
  quarantinedRevocationEnvelopes: [],
  defaultTrustPolicy: DEFAULT_HUB_TRUST_POLICY,
  trustPolicies: {},
};

const FAIL_CLOSED_SWARM_FEED_STATE: SwarmFeedState = {
  findingEnvelopes: [],
  headAnnouncements: [],
  revocationEnvelopes: [],
  quarantinedFindingEnvelopes: [],
  quarantinedHeadAnnouncements: [],
  quarantinedRevocationEnvelopes: [],
  defaultTrustPolicy: FAIL_CLOSED_HUB_TRUST_POLICY,
  trustPolicies: {},
};

function sortFindingEnvelopes(records: SwarmFindingEnvelopeRecord[]): SwarmFindingEnvelopeRecord[] {
  return [...records].sort((left, right) => {
    if (right.envelope.feedSeq !== left.envelope.feedSeq) {
      return right.envelope.feedSeq - left.envelope.feedSeq;
    }
    if (right.envelope.publishedAt !== left.envelope.publishedAt) {
      return right.envelope.publishedAt - left.envelope.publishedAt;
    }
    return right.receivedAt - left.receivedAt;
  });
}

function sortHeadAnnouncements(records: SwarmHeadAnnouncementRecord[]): SwarmHeadAnnouncementRecord[] {
  return [...records].sort((left, right) => {
    if (right.announcement.headSeq !== left.announcement.headSeq) {
      return right.announcement.headSeq - left.announcement.headSeq;
    }
    if (right.announcement.announcedAt !== left.announcement.announcedAt) {
      return right.announcement.announcedAt - left.announcement.announcedAt;
    }
    return right.receivedAt - left.receivedAt;
  });
}

function sortRevocationEnvelopes(
  records: SwarmRevocationEnvelopeRecord[],
): SwarmRevocationEnvelopeRecord[] {
  return [...records].sort((left, right) => {
    if (right.envelope.feedSeq !== left.envelope.feedSeq) {
      return right.envelope.feedSeq - left.envelope.feedSeq;
    }
    if (right.envelope.issuedAt !== left.envelope.issuedAt) {
      return right.envelope.issuedAt - left.envelope.issuedAt;
    }
    return right.receivedAt - left.receivedAt;
  });
}

function findingEnvelopeReplayKey(
  record: Pick<SwarmFindingEnvelopeRecord, "swarmId" | "envelope">,
): string {
  return `${record.swarmId}:${record.envelope.feedId}:${record.envelope.issuerId}:${record.envelope.feedSeq}`;
}

function normalizeHeadAnnouncementLane(value: unknown): SwarmHeadLane {
  return value === REVOCATION_HEAD_LANE ? REVOCATION_HEAD_LANE : FINDING_HEAD_LANE;
}

function headAnnouncementKey(
  record: Pick<SwarmHeadAnnouncementRecord, "swarmId" | "announcement" | "lane">,
): string {
  return `${record.swarmId}:${record.announcement.feedId}:${record.announcement.issuerId}:${normalizeHeadAnnouncementLane(record.lane)}`;
}

function revocationEnvelopeReplayKey(
  record: Pick<SwarmRevocationEnvelopeRecord, "swarmId" | "envelope">,
): string {
  return `${record.swarmId}:${record.envelope.feedId}:${record.envelope.issuerId}:${record.envelope.feedSeq}`;
}

function shouldReplaceFindingEnvelope(
  current: SwarmFindingEnvelopeRecord,
  next: SwarmFindingEnvelopeRecord,
): boolean {
  if (next.envelope.feedSeq !== current.envelope.feedSeq) {
    return next.envelope.feedSeq > current.envelope.feedSeq;
  }
  if (next.envelope.publishedAt !== current.envelope.publishedAt) {
    return next.envelope.publishedAt >= current.envelope.publishedAt;
  }
  return next.receivedAt >= current.receivedAt;
}

function shouldReplaceHeadAnnouncement(
  current: SwarmHeadAnnouncementRecord,
  next: SwarmHeadAnnouncementRecord,
): boolean {
  if (next.announcement.headSeq !== current.announcement.headSeq) {
    return next.announcement.headSeq > current.announcement.headSeq;
  }
  if (next.announcement.announcedAt !== current.announcement.announcedAt) {
    return next.announcement.announcedAt >= current.announcement.announcedAt;
  }
  return next.receivedAt >= current.receivedAt;
}

function shouldReplaceRevocationEnvelope(
  current: SwarmRevocationEnvelopeRecord,
  next: SwarmRevocationEnvelopeRecord,
): boolean {
  if (next.envelope.feedSeq !== current.envelope.feedSeq) {
    return next.envelope.feedSeq > current.envelope.feedSeq;
  }
  if (next.envelope.issuedAt !== current.envelope.issuedAt) {
    return next.envelope.issuedAt >= current.envelope.issuedAt;
  }
  return next.receivedAt >= current.receivedAt;
}

function upsertFindingEnvelope(
  records: SwarmFindingEnvelopeRecord[],
  record: SwarmFindingEnvelopeRecord,
): SwarmFindingEnvelopeRecord[] {
  const index = records.findIndex(
    (entry) => findingEnvelopeReplayKey(entry) === findingEnvelopeReplayKey(record),
  );
  if (index === -1) {
    return sortFindingEnvelopes([...records, record]);
  }

  if (!shouldReplaceFindingEnvelope(records[index]!, record)) {
    return records;
  }

  const next = [...records];
  next[index] = record;
  return sortFindingEnvelopes(next);
}

function upsertHeadAnnouncement(
  records: SwarmHeadAnnouncementRecord[],
  record: SwarmHeadAnnouncementRecord,
): SwarmHeadAnnouncementRecord[] {
  const normalizedRecord: SwarmHeadAnnouncementRecord = {
    ...record,
    lane: normalizeHeadAnnouncementLane(record.lane),
  };
  const index = records.findIndex(
    (entry) => headAnnouncementKey(entry) === headAnnouncementKey(normalizedRecord),
  );
  if (index === -1) {
    return sortHeadAnnouncements([...records, normalizedRecord]);
  }

  if (!shouldReplaceHeadAnnouncement(records[index]!, normalizedRecord)) {
    return records;
  }

  const next = [...records];
  next[index] = normalizedRecord;
  return sortHeadAnnouncements(next);
}

function upsertRevocationEnvelope(
  records: SwarmRevocationEnvelopeRecord[],
  record: SwarmRevocationEnvelopeRecord,
): SwarmRevocationEnvelopeRecord[] {
  const index = records.findIndex(
    (entry) => revocationEnvelopeReplayKey(entry) === revocationEnvelopeReplayKey(record),
  );
  if (index === -1) {
    return sortRevocationEnvelopes([...records, record]);
  }

  if (!shouldReplaceRevocationEnvelope(records[index]!, record)) {
    return records;
  }

  const next = [...records];
  next[index] = record;
  return sortRevocationEnvelopes(next);
}

function mergeFindingEnvelopeRecords(
  ...groups: SwarmFindingEnvelopeRecord[][]
): SwarmFindingEnvelopeRecord[] {
  return groups.flat().reduce<SwarmFindingEnvelopeRecord[]>(
    (records, record) => upsertFindingEnvelope(records, record),
    [],
  );
}

function mergeHeadAnnouncementRecords(
  ...groups: SwarmHeadAnnouncementRecord[][]
): SwarmHeadAnnouncementRecord[] {
  return groups.flat().reduce<SwarmHeadAnnouncementRecord[]>(
    (records, record) => upsertHeadAnnouncement(records, record),
    [],
  );
}

function mergeRevocationEnvelopeRecords(
  ...groups: SwarmRevocationEnvelopeRecord[][]
): SwarmRevocationEnvelopeRecord[] {
  return groups.flat().reduce<SwarmRevocationEnvelopeRecord[]>(
    (records, record) => upsertRevocationEnvelope(records, record),
    [],
  );
}

function hasRecordForReplayKey<RecordType>(
  records: RecordType[],
  record: RecordType,
  getReplayKey: (record: RecordType) => string,
): boolean {
  const replayKey = getReplayKey(record);
  return records.some((entry) => getReplayKey(entry) === replayKey);
}

function upsertFindingEnvelopeAcrossPartitions(
  state: SwarmFeedState,
  record: SwarmFindingEnvelopeRecord,
): Pick<SwarmFeedState, "findingEnvelopes" | "quarantinedFindingEnvelopes"> {
  if (
    !hasRecordForReplayKey(state.findingEnvelopes, record, findingEnvelopeReplayKey) &&
    hasRecordForReplayKey(
      state.quarantinedFindingEnvelopes,
      record,
      findingEnvelopeReplayKey,
    )
  ) {
    return {
      findingEnvelopes: state.findingEnvelopes,
      quarantinedFindingEnvelopes: upsertFindingEnvelope(
        state.quarantinedFindingEnvelopes,
        record,
      ),
    };
  }

  return {
    findingEnvelopes: upsertFindingEnvelope(state.findingEnvelopes, record),
    quarantinedFindingEnvelopes: state.quarantinedFindingEnvelopes,
  };
}

function upsertRevocationEnvelopeAcrossPartitions(
  state: SwarmFeedState,
  record: SwarmRevocationEnvelopeRecord,
): Pick<SwarmFeedState, "revocationEnvelopes" | "quarantinedRevocationEnvelopes"> {
  if (
    !hasRecordForReplayKey(state.revocationEnvelopes, record, revocationEnvelopeReplayKey) &&
    hasRecordForReplayKey(
      state.quarantinedRevocationEnvelopes,
      record,
      revocationEnvelopeReplayKey,
    )
  ) {
    return {
      revocationEnvelopes: state.revocationEnvelopes,
      quarantinedRevocationEnvelopes: upsertRevocationEnvelope(
        state.quarantinedRevocationEnvelopes,
        record,
      ),
    };
  }

  return {
    revocationEnvelopes: upsertRevocationEnvelope(state.revocationEnvelopes, record),
    quarantinedRevocationEnvelopes: state.quarantinedRevocationEnvelopes,
  };
}

type SwarmSingleRecordDuplicateDecision =
  | { kind: "append" }
  | { kind: "idempotent" }
  | { kind: "reject"; reason: "seq_conflict" };

function evaluateSingleRecordDuplicate<RecordType, PayloadType extends FindingEnvelope | RevocationEnvelope>(
  records: RecordType[],
  record: RecordType,
  getReplayKey: (record: RecordType) => string,
  getPayload: (record: RecordType) => PayloadType,
): SwarmSingleRecordDuplicateDecision {
  const matching = records.filter((entry) => getReplayKey(entry) === getReplayKey(record));
  if (matching.length === 0) {
    return { kind: "append" };
  }

  const serializedPayload = serializeProtocolPayload(getPayload(record));
  if (
    matching.every(
      (entry) => serializeProtocolPayload(getPayload(entry)) === serializedPayload,
    )
  ) {
    return { kind: "idempotent" };
  }

  return { kind: "reject", reason: "seq_conflict" };
}

function evaluateFindingSingleRecordDuplicate(
  state: SwarmFeedState,
  record: SwarmFindingEnvelopeRecord,
): SwarmSingleRecordDuplicateDecision {
  return evaluateSingleRecordDuplicate(
    [...state.findingEnvelopes, ...state.quarantinedFindingEnvelopes],
    record,
    findingEnvelopeReplayKey,
    (entry) => entry.envelope,
  );
}

function evaluateRevocationSingleRecordDuplicate(
  state: SwarmFeedState,
  record: SwarmRevocationEnvelopeRecord,
): SwarmSingleRecordDuplicateDecision {
  return evaluateSingleRecordDuplicate(
    [...state.revocationEnvelopes, ...state.quarantinedRevocationEnvelopes],
    record,
    revocationEnvelopeReplayKey,
    (entry) => entry.envelope,
  );
}

function swarmFeedReducer(state: SwarmFeedState, action: SwarmFeedAction): SwarmFeedState {
  switch (action.type) {
    case "INGEST_FINDING_ENVELOPE":
      return {
        ...state,
        ...upsertFindingEnvelopeAcrossPartitions(state, action.record),
      };
    case "REMOVE_FINDING_ENVELOPE":
      return {
        ...state,
        findingEnvelopes: state.findingEnvelopes.filter(
          (record) =>
            !(
              record.swarmId === action.swarmId &&
              record.envelope.feedId === action.feedId &&
              record.envelope.issuerId === action.issuerId &&
              record.envelope.findingId === action.findingId
            ),
        ),
      };
    case "INGEST_HEAD_ANNOUNCEMENT":
      return {
        ...state,
        headAnnouncements: upsertHeadAnnouncement(state.headAnnouncements, action.record),
      };
    case "INGEST_REVOCATION_ENVELOPE":
      return {
        ...state,
        ...upsertRevocationEnvelopeAcrossPartitions(state, action.record),
      };
    case "REMOVE_HEAD_ANNOUNCEMENT":
      return {
        ...state,
        headAnnouncements: state.headAnnouncements.filter(
          (record) =>
            !matchesHeadRecord(
              record,
              action.swarmId,
              action.feedId,
              action.issuerId,
              action.lane ?? FINDING_HEAD_LANE,
            ),
        ),
      };
    case "SET_TRUST_POLICY":
      return applyTrustPolicyChange(state, action.swarmId, action.trustPolicy);
    case "LOAD":
      return action.state;
    default:
      return state;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPromiseLike<T>(value: MaybePromise<T>): value is Promise<T> {
  return typeof value === "object" && value !== null && "then" in value;
}

function hasSameValues<T>(left: readonly T[], right: readonly T[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function isDefaultPermissiveTrustPolicy(policy: HubTrustPolicy): boolean {
  const matchesCurrentAllowedSchemas = hasSameValues(
    policy.allowedSchemas,
    DEFAULT_HUB_TRUST_POLICY.allowedSchemas,
  );
  const matchesLegacyAllowedSchemas = hasSameValues(policy.allowedSchemas, [FINDING_ENVELOPE_SCHEMA]);

  return (
    policy.requireAttestation === DEFAULT_HUB_TRUST_POLICY.requireAttestation &&
    policy.requireWitnessProofs === DEFAULT_HUB_TRUST_POLICY.requireWitnessProofs &&
    hasSameValues(policy.trustedIssuers, DEFAULT_HUB_TRUST_POLICY.trustedIssuers) &&
    hasSameValues(policy.blockedIssuers, DEFAULT_HUB_TRUST_POLICY.blockedIssuers) &&
    (matchesCurrentAllowedSchemas || matchesLegacyAllowedSchemas)
  );
}

function splitSwarmRecords<RecordType extends { swarmId: string }>(
  records: RecordType[],
  swarmId: string,
): { matching: RecordType[]; remaining: RecordType[] } {
  const matching: RecordType[] = [];
  const remaining: RecordType[] = [];

  for (const record of records) {
    if (record.swarmId === swarmId) {
      matching.push(record);
      continue;
    }
    remaining.push(record);
  }

  return {
    matching,
    remaining,
  };
}

function applyTrustPolicyChange(
  state: SwarmFeedState,
  swarmId: string,
  trustPolicy: HubTrustPolicy,
): SwarmFeedState {
  const nextTrustPolicies = {
    ...state.trustPolicies,
    [swarmId]: trustPolicy,
  };
  const { matching: activeFindingEnvelopes, remaining: otherFindingEnvelopes } = splitSwarmRecords(
    state.findingEnvelopes,
    swarmId,
  );
  const {
    matching: quarantinedFindingEnvelopes,
    remaining: otherQuarantinedFindingEnvelopes,
  } = splitSwarmRecords(state.quarantinedFindingEnvelopes, swarmId);
  const { matching: activeHeadAnnouncements, remaining: otherHeadAnnouncements } = splitSwarmRecords(
    state.headAnnouncements,
    swarmId,
  );
  const {
    matching: quarantinedHeadAnnouncements,
    remaining: otherQuarantinedHeadAnnouncements,
  } = splitSwarmRecords(state.quarantinedHeadAnnouncements, swarmId);
  const { matching: activeRevocationEnvelopes, remaining: otherRevocationEnvelopes } =
    splitSwarmRecords(state.revocationEnvelopes, swarmId);
  const {
    matching: quarantinedRevocationEnvelopes,
    remaining: otherQuarantinedRevocationEnvelopes,
  } = splitSwarmRecords(state.quarantinedRevocationEnvelopes, swarmId);

  if (isDefaultPermissiveTrustPolicy(trustPolicy)) {
    // H-3 fix: When relaxing back to a permissive policy, re-evaluate each
    // quarantined record against the new policy before restoring. Only records
    // that pass the policy check are moved to active; records that still fail
    // remain quarantined. Uses synchronous evaluation — records requiring
    // async attestation verification stay quarantined (fail-closed).
    const restoredFindings: SwarmFindingEnvelopeRecord[] = [];
    const stillQuarantinedFindings: SwarmFindingEnvelopeRecord[] = [];
    for (const record of quarantinedFindingEnvelopes) {
      const decision = evaluateFindingTrustPolicySync(trustPolicy, record.envelope);
      if (decision.accepted) {
        restoredFindings.push(record);
      } else {
        stillQuarantinedFindings.push(record);
      }
    }

    const restoredRevocations: SwarmRevocationEnvelopeRecord[] = [];
    const stillQuarantinedRevocations: SwarmRevocationEnvelopeRecord[] = [];
    for (const record of quarantinedRevocationEnvelopes) {
      const decision = evaluateRevocationTrustPolicySync(trustPolicy, record.envelope);
      if (decision.accepted) {
        restoredRevocations.push(record);
      } else {
        stillQuarantinedRevocations.push(record);
      }
    }

    return {
      ...state,
      findingEnvelopes: mergeFindingEnvelopeRecords(
        otherFindingEnvelopes,
        activeFindingEnvelopes,
        restoredFindings,
      ),
      headAnnouncements: mergeHeadAnnouncementRecords(
        otherHeadAnnouncements,
        activeHeadAnnouncements,
        quarantinedHeadAnnouncements,
      ),
      revocationEnvelopes: mergeRevocationEnvelopeRecords(
        otherRevocationEnvelopes,
        activeRevocationEnvelopes,
        restoredRevocations,
      ),
      quarantinedFindingEnvelopes: mergeFindingEnvelopeRecords(
        otherQuarantinedFindingEnvelopes,
        stillQuarantinedFindings,
      ),
      quarantinedHeadAnnouncements: otherQuarantinedHeadAnnouncements,
      quarantinedRevocationEnvelopes: mergeRevocationEnvelopeRecords(
        otherQuarantinedRevocationEnvelopes,
        stillQuarantinedRevocations,
      ),
      trustPolicies: nextTrustPolicies,
    };
  }

  return {
    ...state,
    findingEnvelopes: otherFindingEnvelopes,
    headAnnouncements: otherHeadAnnouncements,
    revocationEnvelopes: otherRevocationEnvelopes,
    quarantinedFindingEnvelopes: mergeFindingEnvelopeRecords(
      otherQuarantinedFindingEnvelopes,
      quarantinedFindingEnvelopes,
      activeFindingEnvelopes,
    ),
    quarantinedHeadAnnouncements: mergeHeadAnnouncementRecords(
      otherQuarantinedHeadAnnouncements,
      quarantinedHeadAnnouncements,
      activeHeadAnnouncements,
    ),
    quarantinedRevocationEnvelopes: mergeRevocationEnvelopeRecords(
      otherQuarantinedRevocationEnvelopes,
      quarantinedRevocationEnvelopes,
      activeRevocationEnvelopes,
    ),
    trustPolicies: nextTrustPolicies,
  };
}

function normalizeFindingEnvelopeRecord(value: unknown): SwarmFindingEnvelopeRecord | null {
  if (!isRecord(value) || typeof value.swarmId !== "string" || !isFindingEnvelope(value.envelope)) {
    return null;
  }

  return {
    swarmId: value.swarmId,
    envelope: value.envelope,
    receivedAt:
      typeof value.receivedAt === "number" && Number.isFinite(value.receivedAt)
        ? value.receivedAt
        : value.envelope.publishedAt,
    digest: isProtocolDigest(value.digest) ? value.digest : undefined,
  };
}

function normalizeHeadAnnouncementRecord(value: unknown): SwarmHeadAnnouncementRecord | null {
  if (!isRecord(value) || typeof value.swarmId !== "string" || !isHeadAnnouncement(value.announcement)) {
    return null;
  }

  return {
    swarmId: value.swarmId,
    lane: normalizeHeadAnnouncementLane(value.lane),
    announcement: value.announcement,
    receivedAt:
      typeof value.receivedAt === "number" && Number.isFinite(value.receivedAt)
        ? value.receivedAt
        : value.announcement.announcedAt,
  };
}

function normalizeRevocationEnvelopeRecord(value: unknown): SwarmRevocationEnvelopeRecord | null {
  if (!isRecord(value) || typeof value.swarmId !== "string" || !isRevocationEnvelope(value.envelope)) {
    return null;
  }

  return {
    swarmId: value.swarmId,
    envelope: value.envelope,
    receivedAt:
      typeof value.receivedAt === "number" && Number.isFinite(value.receivedAt)
        ? value.receivedAt
        : value.envelope.issuedAt,
  };
}

function loadPersistedSwarmFeed(): SwarmFeedState | null {
  try {
    const raw = localStorage.getItem(SWARM_FEED_STORAGE_KEY);
    if (!raw) return null;

    const parsed = JSON.parse(raw);
    if (!isRecord(parsed)) {
      return FAIL_CLOSED_SWARM_FEED_STATE;
    }

    const findingEnvelopes = Array.isArray(parsed.findingEnvelopes)
      ? sortFindingEnvelopes(
          parsed.findingEnvelopes.flatMap((value: unknown) => {
            const record = normalizeFindingEnvelopeRecord(value);
            return record ? [record] : [];
          }),
        )
      : [];
    const headAnnouncements = Array.isArray(parsed.headAnnouncements)
      ? sortHeadAnnouncements(
          parsed.headAnnouncements.flatMap((value: unknown) => {
            const record = normalizeHeadAnnouncementRecord(value);
            return record ? [record] : [];
          }),
        )
      : [];
    const revocationEnvelopes = Array.isArray(parsed.revocationEnvelopes)
      ? sortRevocationEnvelopes(
          parsed.revocationEnvelopes.flatMap((value: unknown) => {
            const record = normalizeRevocationEnvelopeRecord(value);
            return record ? [record] : [];
          }),
        )
      : [];
    const quarantinedFindingEnvelopes = Array.isArray(parsed.quarantinedFindingEnvelopes)
      ? sortFindingEnvelopes(
          parsed.quarantinedFindingEnvelopes.flatMap((value: unknown) => {
            const record = normalizeFindingEnvelopeRecord(value);
            return record ? [record] : [];
          }),
        )
      : [];
    const quarantinedHeadAnnouncements = Array.isArray(parsed.quarantinedHeadAnnouncements)
      ? sortHeadAnnouncements(
          parsed.quarantinedHeadAnnouncements.flatMap((value: unknown) => {
            const record = normalizeHeadAnnouncementRecord(value);
            return record ? [record] : [];
          }),
        )
      : [];
    const quarantinedRevocationEnvelopes = Array.isArray(parsed.quarantinedRevocationEnvelopes)
      ? sortRevocationEnvelopes(
          parsed.quarantinedRevocationEnvelopes.flatMap((value: unknown) => {
            const record = normalizeRevocationEnvelopeRecord(value);
            return record ? [record] : [];
          }),
        )
      : [];
    const defaultTrustPolicy =
      parsed.defaultTrustPolicy === undefined
        ? INITIAL_SWARM_FEED_STATE.defaultTrustPolicy
        : isHubTrustPolicy(parsed.defaultTrustPolicy)
          ? parsed.defaultTrustPolicy
          : FAIL_CLOSED_HUB_TRUST_POLICY;
    const hasPersistedTrustPolicies =
      parsed.trustPolicies !== undefined;
    const trustPolicies = isRecord(parsed.trustPolicies)
      ? Object.fromEntries(
          Object.entries(parsed.trustPolicies).map(([swarmId, policy]) => [
            swarmId,
            isHubTrustPolicy(policy) ? policy : FAIL_CLOSED_HUB_TRUST_POLICY,
          ]),
        )
      : {};

    const persistedState: SwarmFeedState = {
      findingEnvelopes,
      headAnnouncements,
      revocationEnvelopes,
      quarantinedFindingEnvelopes,
      quarantinedHeadAnnouncements,
      quarantinedRevocationEnvelopes,
      defaultTrustPolicy: hasPersistedTrustPolicies && !isRecord(parsed.trustPolicies)
        ? FAIL_CLOSED_HUB_TRUST_POLICY
        : defaultTrustPolicy,
      trustPolicies,
    };

    // H-4 fix: Re-evaluate every persisted active record against its stored
    // trust policy. Records that fail the policy check are moved to quarantine
    // rather than being blindly restored to active. This prevents localStorage
    // reload from bypassing trust enforcement. Uses synchronous evaluation —
    // records requiring async attestation verification remain quarantined
    // (fail-closed). For non-permissive policies, all records are quarantined
    // and must be re-validated asynchronously before reuse.
    const isPermissiveSwarm = (swarmId: string): boolean =>
      isDefaultPermissiveTrustPolicy(selectTrustPolicy(persistedState, swarmId));

    const restoredFindingEnvelopes: SwarmFindingEnvelopeRecord[] = [];
    const quarantinedOnReloadFindings: SwarmFindingEnvelopeRecord[] = [];
    for (const record of persistedState.findingEnvelopes) {
      if (!isPermissiveSwarm(record.swarmId)) {
        // Non-permissive: quarantine until async re-validation.
        quarantinedOnReloadFindings.push(record);
        continue;
      }
      const policy = selectTrustPolicy(persistedState, record.swarmId);
      const decision = evaluateFindingTrustPolicySync(policy, record.envelope);
      if (decision.accepted) {
        restoredFindingEnvelopes.push(record);
      } else {
        quarantinedOnReloadFindings.push(record);
      }
    }

    const restoredRevocationEnvelopes: SwarmRevocationEnvelopeRecord[] = [];
    const quarantinedOnReloadRevocations: SwarmRevocationEnvelopeRecord[] = [];
    for (const record of persistedState.revocationEnvelopes) {
      if (!isPermissiveSwarm(record.swarmId)) {
        quarantinedOnReloadRevocations.push(record);
        continue;
      }
      const policy = selectTrustPolicy(persistedState, record.swarmId);
      const decision = evaluateRevocationTrustPolicySync(policy, record.envelope);
      if (decision.accepted) {
        restoredRevocationEnvelopes.push(record);
      } else {
        quarantinedOnReloadRevocations.push(record);
      }
    }

    // Head announcements lack trust-evaluable fields. Restore heads only for
    // swarms whose persisted policy is the default permissive template.
    const restoredHeadAnnouncements = persistedState.headAnnouncements.filter((record) =>
      isPermissiveSwarm(record.swarmId),
    );

    return {
      ...persistedState,
      // Strict or fail-closed policies must revalidate persisted hub data asynchronously before reuse.
      findingEnvelopes: restoredFindingEnvelopes,
      headAnnouncements: restoredHeadAnnouncements,
      revocationEnvelopes: restoredRevocationEnvelopes,
      quarantinedFindingEnvelopes: mergeFindingEnvelopeRecords(
        persistedState.quarantinedFindingEnvelopes,
        quarantinedOnReloadFindings,
      ),
      quarantinedHeadAnnouncements: mergeHeadAnnouncementRecords(
        persistedState.quarantinedHeadAnnouncements,
        persistedState.headAnnouncements.filter(
          (record) => !isPermissiveSwarm(record.swarmId),
        ),
      ),
      quarantinedRevocationEnvelopes: mergeRevocationEnvelopeRecords(
        persistedState.quarantinedRevocationEnvelopes,
        quarantinedOnReloadRevocations,
      ),
    };
  } catch (error) {
    console.warn("[swarm-feed-store] loadPersistedSwarmFeed failed:", error);
    return FAIL_CLOSED_SWARM_FEED_STATE;
  }
}

// SECURITY NOTE: All feed data — including quarantined records — is stored in
// plaintext localStorage. Quarantined data should be treated as untrusted on
// reload and must be re-evaluated against the active trust policy before
// restoration. Do not assume localStorage contents are tamper-proof; any data
// read back must pass trust policy checks before being placed in active state.
function persistSwarmFeed(state: SwarmFeedState): void {
  try {
    localStorage.setItem(
      SWARM_FEED_STORAGE_KEY,
      JSON.stringify({
        findingEnvelopes: state.findingEnvelopes,
        headAnnouncements: state.headAnnouncements,
        revocationEnvelopes: state.revocationEnvelopes,
        quarantinedFindingEnvelopes: state.quarantinedFindingEnvelopes,
        quarantinedHeadAnnouncements: state.quarantinedHeadAnnouncements,
        quarantinedRevocationEnvelopes: state.quarantinedRevocationEnvelopes,
        defaultTrustPolicy: state.defaultTrustPolicy,
        trustPolicies: state.trustPolicies,
      }),
    );
  } catch (error) {
    console.error("[swarm-feed-store] persistSwarmFeed failed:", error);
  }
}

function getInitialState(): SwarmFeedState {
  return loadPersistedSwarmFeed() ?? INITIAL_SWARM_FEED_STATE;
}

function selectTrustPolicy(state: SwarmFeedState, swarmId: string): HubTrustPolicy {
  return state.trustPolicies[swarmId] ?? state.defaultTrustPolicy;
}

function matchesFindingRecord(
  record: SwarmFindingEnvelopeRecord,
  swarmId: string,
  feedId: string,
  issuerId?: string,
): boolean {
  return (
    record.swarmId === swarmId &&
    record.envelope.feedId === feedId &&
    (issuerId === undefined || record.envelope.issuerId === issuerId)
  );
}

function matchesHeadRecord(
  record: SwarmHeadAnnouncementRecord,
  swarmId: string,
  feedId: string,
  issuerId: string,
  lane: SwarmHeadLane = FINDING_HEAD_LANE,
): boolean {
  return (
    record.swarmId === swarmId &&
    record.lane === lane &&
    record.announcement.feedId === feedId &&
    record.announcement.issuerId === issuerId
  );
}

function findingReferenceKey(
  swarmId: string,
  feedId: string,
  issuerId: string,
  findingId: string,
): string {
  return `${swarmId}:${feedId}:${issuerId}:${findingId}`;
}

function findingRevisionKey(
  swarmId: string,
  feedId: string,
  issuerId: string,
  findingId: string,
  digest?: ProtocolDigest,
): string {
  return `${swarmId}:${feedId}:${issuerId}:${findingId}:${digest ?? ""}`;
}

function selectNewestRevocationRecord(
  ...records: Array<SwarmRevocationEnvelopeRecord | undefined>
): SwarmRevocationEnvelopeRecord | undefined {
  return records.reduce<SwarmRevocationEnvelopeRecord | undefined>((latest, record) => {
    if (!record) {
      return latest;
    }
    if (!latest || shouldReplaceRevocationEnvelope(latest, record)) {
      return record;
    }
    return latest;
  }, undefined);
}

function revocationAppliesToFindingRecord(
  record: SwarmRevocationEnvelopeRecord,
  findingRecord?: SwarmFindingEnvelopeRecord,
): boolean {
  if (record.envelope.target.schema !== FINDING_ENVELOPE_SCHEMA) {
    return false;
  }
  if (!findingRecord) {
    return true;
  }
  if (record.envelope.target.id !== findingRecord.envelope.findingId) {
    return false;
  }
  if (record.envelope.target.digest === undefined) {
    return true;
  }
  return findingRecord.digest !== undefined && record.envelope.target.digest === findingRecord.digest;
}

function matchesRevocationRecord(
  record: SwarmRevocationEnvelopeRecord,
  swarmId: string,
  feedId: string,
  findingId: string,
  issuerId?: string,
  findingRecord?: SwarmFindingEnvelopeRecord,
): boolean {
  const targetIssuerId = issuerId ?? findingRecord?.envelope.issuerId;
  return (
    record.swarmId === swarmId &&
    record.envelope.feedId === feedId &&
    (targetIssuerId === undefined || record.envelope.issuerId === targetIssuerId) &&
    record.envelope.target.id === findingId &&
    revocationAppliesToFindingRecord(record, findingRecord)
  );
}

function selectLatestFindingRecord(
  state: SwarmFeedState,
  swarmId: string,
  feedId: string,
  findingId: string,
  issuerId?: string,
  digest?: ProtocolDigest,
): SwarmFindingEnvelopeRecord | undefined {
  return state.findingEnvelopes
    .filter(
      (record) =>
        matchesFindingRecord(record, swarmId, feedId, issuerId) &&
        record.envelope.findingId === findingId &&
        (digest === undefined || record.digest === digest),
    )
    .reduce<SwarmFindingEnvelopeRecord | null>((latest, record) => {
      if (latest === null) {
        return record;
      }
      return shouldReplaceFindingEnvelope(latest, record) ? record : latest;
    }, null)
    ?? undefined;
}

function selectLatestRevocationRecord(
  state: SwarmFeedState,
  swarmId: string,
  feedId: string,
  findingId: string,
  issuerId?: string,
  findingRecord?: SwarmFindingEnvelopeRecord,
): SwarmRevocationEnvelopeRecord | undefined {
  return state.revocationEnvelopes
    .filter(
      (record) =>
        matchesRevocationRecord(record, swarmId, feedId, findingId, issuerId, findingRecord),
    )
    .reduce<SwarmRevocationEnvelopeRecord | undefined>(
      (latest, record) => selectNewestRevocationRecord(latest, record),
      undefined,
    );
}

export function resolveSwarmFindingReference(
  state: SwarmFeedState,
  swarmId: string,
  feedId: string,
  findingId: string,
  issuerId?: string,
): SwarmFindingReferenceResolution | null {
  const findingRecord = selectLatestFindingRecord(state, swarmId, feedId, findingId, issuerId);
  const revocationRecord = selectLatestRevocationRecord(
    state,
    swarmId,
    feedId,
    findingId,
    issuerId,
    findingRecord,
  );

  if (!findingRecord && !revocationRecord) {
    return null;
  }

  if (!revocationRecord) {
    return findingRecord
      ? {
          status: "active",
          swarmId,
          feedId,
          findingId,
          envelope: findingRecord.envelope,
        }
      : null;
  }

  if (
    revocationRecord.envelope.action !== "supersede" ||
    revocationRecord.envelope.replacement === undefined
  ) {
    return {
      status: "revoked",
      swarmId,
      feedId,
      findingId,
      envelope: findingRecord?.envelope,
      revocation: revocationRecord.envelope,
    };
  }

  const replacement = revocationRecord.envelope.replacement;
  const replacementEnvelope =
    replacement.schema === FINDING_ENVELOPE_SCHEMA
      ? selectLatestFindingRecord(
          state,
          swarmId,
          feedId,
          replacement.id,
          revocationRecord.envelope.issuerId,
          replacement.digest,
        )?.envelope
      : undefined;

  return {
    status: "superseded",
    swarmId,
    feedId,
    findingId,
    envelope: findingRecord?.envelope,
    revocation: revocationRecord.envelope,
    replacement: {
      ...replacement,
      envelope: replacementEnvelope,
    },
  };
}

function selectLatestProjectedRevocationRecord(
  latestRevocationRecords: Map<string, SwarmRevocationEnvelopeRecord>,
  findingRecord: SwarmFindingEnvelopeRecord,
): SwarmRevocationEnvelopeRecord | undefined {
  return selectNewestRevocationRecord(
    latestRevocationRecords.get(
      findingRevisionKey(
        findingRecord.swarmId,
        findingRecord.envelope.feedId,
        findingRecord.envelope.issuerId,
        findingRecord.envelope.findingId,
      ),
    ),
    findingRecord.digest
      ? latestRevocationRecords.get(
          findingRevisionKey(
            findingRecord.swarmId,
            findingRecord.envelope.feedId,
            findingRecord.envelope.issuerId,
            findingRecord.envelope.findingId,
            findingRecord.digest,
          ),
        )
      : undefined,
  );
}

function resolveProjectedActiveFindingRecord(
  latestFindingRecords: Map<string, SwarmFindingEnvelopeRecord>,
  latestFindingRevisionRecords: Map<string, SwarmFindingEnvelopeRecord>,
  latestRevocationRecords: Map<string, SwarmRevocationEnvelopeRecord>,
  findingRecord: SwarmFindingEnvelopeRecord,
  seen: Set<string> = new Set(),
): { record: SwarmFindingEnvelopeRecord; sourceFindingIds: string[] } | null {
  const key = findingRevisionKey(
    findingRecord.swarmId,
    findingRecord.envelope.feedId,
    findingRecord.envelope.issuerId,
    findingRecord.envelope.findingId,
    findingRecord.digest,
  );
  if (seen.has(key)) {
    return null;
  }

  const revocationRecord = selectLatestProjectedRevocationRecord(latestRevocationRecords, findingRecord);
  if (!revocationRecord) {
    return {
      record: findingRecord,
      sourceFindingIds: [findingRecord.envelope.findingId],
    };
  }

  if (
    revocationRecord.envelope.action !== "supersede" ||
    revocationRecord.envelope.replacement === undefined ||
    revocationRecord.envelope.replacement.schema !== FINDING_ENVELOPE_SCHEMA
  ) {
    return null;
  }

  const replacementRecord =
    revocationRecord.envelope.replacement.digest !== undefined
      ? latestFindingRevisionRecords.get(
          findingRevisionKey(
            findingRecord.swarmId,
            findingRecord.envelope.feedId,
            revocationRecord.envelope.issuerId,
            revocationRecord.envelope.replacement.id,
            revocationRecord.envelope.replacement.digest,
          ),
        )
      : latestFindingRecords.get(
          findingReferenceKey(
            findingRecord.swarmId,
            findingRecord.envelope.feedId,
            revocationRecord.envelope.issuerId,
            revocationRecord.envelope.replacement.id,
          ),
        );
  if (!replacementRecord) {
    return null;
  }

  const nextSeen = new Set(seen);
  nextSeen.add(key);
  const resolvedReplacement = resolveProjectedActiveFindingRecord(
    latestFindingRecords,
    latestFindingRevisionRecords,
    latestRevocationRecords,
    replacementRecord,
    nextSeen,
  );
  if (!resolvedReplacement) {
    return null;
  }

  return {
    record: resolvedReplacement.record,
    sourceFindingIds: [findingRecord.envelope.findingId, ...resolvedReplacement.sourceFindingIds],
  };
}

function collectLatestFindingRecords(state: SwarmFeedState): Map<string, SwarmFindingEnvelopeRecord> {
  const latestRecords = new Map<string, SwarmFindingEnvelopeRecord>();
  for (const record of state.findingEnvelopes) {
    const key = findingReferenceKey(
      record.swarmId,
      record.envelope.feedId,
      record.envelope.issuerId,
      record.envelope.findingId,
    );
    const current = latestRecords.get(key);
    if (!current || shouldReplaceFindingEnvelope(current, record)) {
      latestRecords.set(key, record);
    }
  }
  return latestRecords;
}

function collectLatestFindingRevisionRecords(
  state: SwarmFeedState,
): Map<string, SwarmFindingEnvelopeRecord> {
  const latestRecords = new Map<string, SwarmFindingEnvelopeRecord>();
  for (const record of state.findingEnvelopes) {
    const key = findingRevisionKey(
      record.swarmId,
      record.envelope.feedId,
      record.envelope.issuerId,
      record.envelope.findingId,
      record.digest,
    );
    const current = latestRecords.get(key);
    if (!current || shouldReplaceFindingEnvelope(current, record)) {
      latestRecords.set(key, record);
    }
  }
  return latestRecords;
}

function collectLatestRevocationRecords(
  state: SwarmFeedState,
): Map<string, SwarmRevocationEnvelopeRecord> {
  const latestRecords = new Map<string, SwarmRevocationEnvelopeRecord>();
  for (const record of state.revocationEnvelopes) {
    if (record.envelope.target.schema !== FINDING_ENVELOPE_SCHEMA) {
      continue;
    }
    const key = findingRevisionKey(
      record.swarmId,
      record.envelope.feedId,
      record.envelope.issuerId,
      record.envelope.target.id,
      record.envelope.target.digest,
    );
    const current = latestRecords.get(key);
    if (!current || shouldReplaceRevocationEnvelope(current, record)) {
      latestRecords.set(key, record);
    }
  }
  return latestRecords;
}

async function hydrateFindingEnvelopeRecordDigest(
  record: SwarmFindingEnvelopeRecord,
): Promise<SwarmFindingEnvelopeRecord> {
  if (record.digest !== undefined) {
    return record;
  }
  return {
    ...record,
    digest: await hashProtocolPayload(record.envelope),
  };
}

function sortProjectedFindingRecords(
  records: SwarmProjectedFindingRecord[],
): SwarmProjectedFindingRecord[] {
  return [...records].sort((left, right) => {
    if (right.envelope.feedSeq !== left.envelope.feedSeq) {
      return right.envelope.feedSeq - left.envelope.feedSeq;
    }
    if (right.envelope.publishedAt !== left.envelope.publishedAt) {
      return right.envelope.publishedAt - left.envelope.publishedAt;
    }
    return right.receivedAt - left.receivedAt;
  });
}

export function selectProjectedFindingRecords(state: SwarmFeedState): SwarmProjectedFindingRecord[] {
  const latestFindingRecords = collectLatestFindingRecords(state);
  const latestFindingRevisionRecords = collectLatestFindingRevisionRecords(state);
  const latestRevocationRecords = collectLatestRevocationRecords(state);
  const projectedRecords = new Map<
    string,
    {
      record: SwarmFindingEnvelopeRecord;
      sourceFindingIds: Set<string>;
    }
  >();

  for (const record of latestFindingRecords.values()) {
    const resolved = resolveProjectedActiveFindingRecord(
      latestFindingRecords,
      latestFindingRevisionRecords,
      latestRevocationRecords,
      record,
    );
    if (!resolved) {
      continue;
    }

    const projectedKey = findingRevisionKey(
      resolved.record.swarmId,
      resolved.record.envelope.feedId,
      resolved.record.envelope.issuerId,
      resolved.record.envelope.findingId,
      resolved.record.digest,
    );
    const existing = projectedRecords.get(projectedKey);
    if (!existing) {
      projectedRecords.set(projectedKey, {
        record: resolved.record,
        sourceFindingIds: new Set(resolved.sourceFindingIds),
      });
      continue;
    }

    if (shouldReplaceFindingEnvelope(existing.record, resolved.record)) {
      existing.record = resolved.record;
    }
    for (const sourceFindingId of resolved.sourceFindingIds) {
      existing.sourceFindingIds.add(sourceFindingId);
    }
  }

  return sortProjectedFindingRecords(
    Array.from(projectedRecords.values()).map(({ record, sourceFindingIds }) => ({
      ...record,
      sourceFindingIds: Array.from(sourceFindingIds).sort(),
    })),
  );
}

function selectLatestFindingSeq(
  state: SwarmFeedState,
  swarmId: string,
  feedId: string,
  issuerId?: string,
): number | null {
  return state.findingEnvelopes
    .filter((record) => matchesFindingRecord(record, swarmId, feedId, issuerId))
    .reduce<number | null>(
      (latest, record) =>
        latest === null ? record.envelope.feedSeq : Math.max(latest, record.envelope.feedSeq),
      null,
    );
}

function selectLatestFindingEnvelope(
  state: SwarmFeedState,
  swarmId: string,
  feedId: string,
  findingId: string,
  issuerId?: string,
  digest?: ProtocolDigest,
): FindingEnvelope | undefined {
  return selectLatestFindingRecord(state, swarmId, feedId, findingId, issuerId, digest)?.envelope;
}

function selectLatestHeadSeq(
  state: SwarmFeedState,
  swarmId: string,
  feedId: string,
  issuerId: string,
  lane: SwarmHeadLane = FINDING_HEAD_LANE,
): number | null {
  return state.headAnnouncements
    .filter((record) => matchesHeadRecord(record, swarmId, feedId, issuerId, lane))
    .reduce<number | null>(
      (latest, record) =>
        latest === null
          ? record.announcement.headSeq
          : Math.max(latest, record.announcement.headSeq),
      null,
    );
}

function listFindingSeqsForReplayTarget(
  state: SwarmFeedState,
  swarmId: string,
  feedId: string,
  issuerId: string,
): number[] {
  return [...state.findingEnvelopes, ...state.quarantinedFindingEnvelopes]
    .filter((record) => matchesFindingRecord(record, swarmId, feedId, issuerId))
    .map((record) => record.envelope.feedSeq);
}

function selectReplayProgress(
  state: SwarmFeedState,
  swarmId: string,
  feedId: string,
  issuerId: string,
) {
  return summarizeSwarmReplayProgress(
    listFindingSeqsForReplayTarget(state, swarmId, feedId, issuerId),
  );
}

export function getSwarmFeedSyncState(
  state: SwarmFeedState,
  swarmId: string,
  feedId: string,
  issuerId: string,
): SwarmFeedSyncState {
  const replayProgress = selectReplayProgress(state, swarmId, feedId, issuerId);
  return {
    swarmId,
    feedId,
    issuerId,
    localFindingSeq: replayProgress.contiguousSeq,
    localMaxFindingSeq: replayProgress.highestSeenSeq,
    localHeadSeq: selectLatestHeadSeq(state, swarmId, feedId, issuerId),
  };
}

export function deriveSwarmReplayRequest(
  state: SwarmFeedState,
  swarmId: string,
  remoteHead: HeadAnnouncement,
  options?: { maxEntries?: number },
): SwarmReplayRequest | null {
  if (!isHeadAnnouncement(remoteHead)) {
    return null;
  }

  return planSwarmReplay({
    ...getSwarmFeedSyncState(state, swarmId, remoteHead.feedId, remoteHead.issuerId),
    remoteHeadSeq: remoteHead.headSeq,
    maxEntries: options?.maxEntries,
  }).request;
}

function buildTrustedReplayBatch(
  batch: SwarmReplayBatch,
  decisions: Array<FindingTrustPolicyDecision | null>,
): {
  filteredBatch: SwarmReplayBatch;
  trustRejectedEnvelopes: SwarmReplayTrustRejectedEnvelope[];
} {
  const trustRejectedEnvelopes: SwarmReplayTrustRejectedEnvelope[] = [];
  const filteredBatch: SwarmReplayBatch = {
    ...batch,
    envelopes: batch.envelopes.flatMap((envelope, index) => {
      const decision = decisions[index] ?? null;
      if (decision === null || decision.accepted) {
        return [envelope];
      }

      trustRejectedEnvelopes.push({
        envelope,
        reason: decision.reason,
      });
      return [];
    }),
  };

  return {
    filteredBatch,
    trustRejectedEnvelopes,
  };
}

function evaluateReplayBatchTrustPolicy(
  trustPolicy: HubTrustPolicy,
  batch: SwarmReplayBatch,
): MaybePromise<{
  filteredBatch: SwarmReplayBatch;
  trustRejectedEnvelopes: SwarmReplayTrustRejectedEnvelope[];
}> {
  const decisions = batch.envelopes.map((envelope) =>
    isFindingEnvelope(envelope) ? evaluateFindingTrustPolicy(trustPolicy, envelope) : null,
  );
  const hasAsyncDecision = decisions.some(
    (decision): decision is Promise<FindingTrustPolicyDecision> => decision !== null && isPromiseLike(decision),
  );

  if (!hasAsyncDecision) {
    return buildTrustedReplayBatch(
      batch,
      decisions as Array<FindingTrustPolicyDecision | null>,
    );
  }

  return Promise.all(
    decisions.map((decision) =>
      decision === null ? Promise.resolve(null) : Promise.resolve(decision),
    ),
  ).then((resolved) => buildTrustedReplayBatch(batch, resolved));
}

export function ingestSwarmReplayBatchIntoState(
  state: SwarmFeedState,
  request: SwarmReplayRequest,
  batch: SwarmReplayBatch,
  receivedAt: number = Date.now(),
): { state: SwarmFeedState; validationResult: SwarmReplayValidationResult } {
  const validationResult = validateSwarmReplayBatch({
    request,
    batch,
    existingSeqs: listFindingSeqsForReplayTarget(
      state,
      request.swarmId,
      request.feedId,
      request.issuerId,
    ),
    currentHeadSeq: selectLatestHeadSeq(
      state,
      request.swarmId,
      request.feedId,
      request.issuerId,
    ),
  });

  let nextState = state;

  for (const envelope of validationResult.acceptedEnvelopes) {
    nextState = {
      ...nextState,
      findingEnvelopes: upsertFindingEnvelope(nextState.findingEnvelopes, {
        swarmId: request.swarmId,
        envelope,
        receivedAt,
      }),
    };
  }

  if (validationResult.appliedHeadAnnouncement) {
    nextState = {
      ...nextState,
      headAnnouncements: upsertHeadAnnouncement(nextState.headAnnouncements, {
        swarmId: request.swarmId,
          lane: FINDING_HEAD_LANE,
        announcement: validationResult.appliedHeadAnnouncement,
        receivedAt,
      }),
    };
  }

  return {
    state: nextState,
    validationResult,
  };
}

export type SwarmSingleRecordIngestRejectionReason =
  | FindingTrustPolicyRejectionReason
  | "seq_conflict";
export type SwarmSingleRecordIngestResult =
  | { accepted: true }
  | { accepted: false; reason: SwarmSingleRecordIngestRejectionReason };
export type SwarmFindingIngestResult = SwarmSingleRecordIngestResult;
export type SwarmRevocationIngestResult = SwarmSingleRecordIngestResult;

export interface SwarmReplayTrustRejectedEnvelope {
  envelope: FindingEnvelope;
  reason: FindingTrustPolicyRejectionReason;
}

export interface SwarmReplayIngestResult {
  validationResult: SwarmReplayValidationResult;
  trustRejectedEnvelopes: SwarmReplayTrustRejectedEnvelope[];
}

interface SwarmFeedContextValue {
  findingEnvelopeRecords: SwarmFindingEnvelopeRecord[];
  headAnnouncementRecords: SwarmHeadAnnouncementRecord[];
  revocationEnvelopeRecords: SwarmRevocationEnvelopeRecord[];
  projectedFindingRecords: SwarmProjectedFindingRecord[];
  findingEnvelopes: FindingEnvelope[];
  headAnnouncements: HeadAnnouncement[];
  revocationEnvelopes: RevocationEnvelope[];
  getTrustPolicy: (swarmId: string) => HubTrustPolicy;
  setTrustPolicy: (swarmId: string, trustPolicy: HubTrustPolicy) => void;
  ingestFindingEnvelope: (record: SwarmFindingEnvelopeRecord) => MaybePromise<SwarmFindingIngestResult>;
  removeFindingEnvelope: (swarmId: string, feedId: string, issuerId: string, findingId: string) => void;
  ingestHeadAnnouncement: (record: SwarmHeadAnnouncementRecord) => void;
  removeHeadAnnouncement: (swarmId: string, feedId: string, issuerId: string) => void;
  ingestRevocationEnvelope: (
    record: SwarmRevocationEnvelopeRecord,
  ) => MaybePromise<SwarmRevocationIngestResult>;
  getFindingEnvelope: (
    swarmId: string,
    feedId: string,
    issuerId: string,
    findingId: string,
  ) => FindingEnvelope | undefined;
  resolveFindingReference: (
    swarmId: string,
    feedId: string,
    issuerId: string,
    findingId: string,
  ) => SwarmFindingReferenceResolution | null;
  listFindingEnvelopesForSwarm: (swarmId: string) => FindingEnvelope[];
  listFindingEnvelopesForFeed: (swarmId: string, feedId: string) => FindingEnvelope[];
  getHeadAnnouncement: (swarmId: string, feedId: string, issuerId: string) => HeadAnnouncement | undefined;
  listHeadAnnouncementsForSwarm: (swarmId: string) => HeadAnnouncement[];
  listHeadAnnouncementsForFeed: (swarmId: string, feedId: string) => HeadAnnouncement[];
  getLatestFindingSeq: (swarmId: string, feedId: string) => number | null;
  getLatestHeadSeq: (swarmId: string, feedId: string, issuerId: string) => number | null;
  getFeedSyncState: (swarmId: string, feedId: string, issuerId: string) => SwarmFeedSyncState;
  deriveReplayRequest: (
    swarmId: string,
    remoteHead: HeadAnnouncement,
    options?: { maxEntries?: number },
  ) => SwarmReplayRequest | null;
  ingestReplayBatch: (
    request: SwarmReplayRequest,
    batch: SwarmReplayBatch,
    receivedAt?: number,
  ) => MaybePromise<SwarmReplayIngestResult>;
}

const SwarmFeedContext = createContext<SwarmFeedContextValue | null>(null);

export function useSwarmFeed(): SwarmFeedContextValue {
  const ctx = useContext(SwarmFeedContext);
  if (!ctx) {
    throw new Error("useSwarmFeed must be used within SwarmFeedProvider");
  }
  return ctx;
}

export function SwarmFeedProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(swarmFeedReducer, undefined, getInitialState);
  const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const digestHydrationRef = useRef<Set<string>>(new Set());
  const stateRef = useRef(state);

  stateRef.current = state;

  const dispatchAndSync = useCallback(
    (action: SwarmFeedAction) => {
      stateRef.current = swarmFeedReducer(stateRef.current, action);
      dispatch(action);
    },
    [dispatch],
  );

  const queueFindingDigestHydration = useCallback(
    (record: SwarmFindingEnvelopeRecord) => {
      if (record.digest !== undefined) {
        return;
      }
      const replayKey = findingEnvelopeReplayKey(record);
      if (digestHydrationRef.current.has(replayKey)) {
        return;
      }
      digestHydrationRef.current.add(replayKey);
      void hydrateFindingEnvelopeRecordDigest(record)
        .then((hydratedRecord) => {
          dispatchAndSync({ type: "INGEST_FINDING_ENVELOPE", record: hydratedRecord });
        })
        .catch((error) => {
          console.warn("[swarm-feed-store] finding digest hydration failed:", error);
        })
        .finally(() => {
          digestHydrationRef.current.delete(replayKey);
        });
    },
    [dispatchAndSync],
  );

  useEffect(() => {
    for (const record of state.findingEnvelopes) {
      queueFindingDigestHydration(record);
    }
  }, [queueFindingDigestHydration, state.findingEnvelopes]);

  useEffect(() => {
    if (persistRef.current) {
      clearTimeout(persistRef.current);
    }
    persistRef.current = setTimeout(() => {
      persistSwarmFeed(state);
      persistRef.current = null;
    }, 500);

    return () => {
      if (persistRef.current) {
        clearTimeout(persistRef.current);
      }
    };
  }, [
    state.defaultTrustPolicy,
    state.findingEnvelopes,
    state.headAnnouncements,
    state.revocationEnvelopes,
    state.quarantinedFindingEnvelopes,
    state.quarantinedHeadAnnouncements,
    state.quarantinedRevocationEnvelopes,
    state.trustPolicies,
  ]);

    useEffect(() => {
    const handleBeforeUnload = () => {
      if (persistRef.current) {
        clearTimeout(persistRef.current);
        persistRef.current = null;
        persistSwarmFeed(stateRef.current);
      }
    };
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => {
      window.removeEventListener("beforeunload", handleBeforeUnload);
    };
  }, []);

  const getTrustPolicy = useCallback(
    (swarmId: string) => selectTrustPolicy(state, swarmId),
    [state.trustPolicies],
  );

  const setTrustPolicy = useCallback((swarmId: string, trustPolicy: HubTrustPolicy) => {
    dispatchAndSync({ type: "SET_TRUST_POLICY", swarmId, trustPolicy });
  }, [dispatchAndSync]);

  const ingestFindingEnvelope = useCallback(
    (record: SwarmFindingEnvelopeRecord): MaybePromise<SwarmFindingIngestResult> => {
      const result = evaluateFindingTrustPolicy(
        selectTrustPolicy(stateRef.current, record.swarmId),
        record.envelope,
      );

      const finalizeFindingIngest = (
        resolved: FindingTrustPolicyDecision,
      ): SwarmFindingIngestResult => {
        if (!resolved.accepted) {
          return resolved;
        }

        const duplicateDecision = evaluateFindingSingleRecordDuplicate(stateRef.current, record);
        if (duplicateDecision.kind === "reject") {
          return {
            accepted: false,
            reason: duplicateDecision.reason,
          };
        }
        if (duplicateDecision.kind === "append") {
          dispatchAndSync({ type: "INGEST_FINDING_ENVELOPE", record });
          queueFindingDigestHydration(record);
        }

        return { accepted: true };
      };

      if (isPromiseLike(result)) {
        return result.then(finalizeFindingIngest);
      }

      return finalizeFindingIngest(result);
    },
    [dispatchAndSync, queueFindingDigestHydration],
  );

  const removeFindingEnvelope = useCallback((
    swarmId: string,
    feedId: string,
    issuerId: string,
    findingId: string,
  ) => {
    dispatchAndSync({ type: "REMOVE_FINDING_ENVELOPE", swarmId, feedId, issuerId, findingId });
  }, [dispatchAndSync]);

  const ingestHeadAnnouncement = useCallback((record: SwarmHeadAnnouncementRecord) => {
    dispatchAndSync({ type: "INGEST_HEAD_ANNOUNCEMENT", record });
  }, [dispatchAndSync]);

  const removeHeadAnnouncement = useCallback((swarmId: string, feedId: string, issuerId: string) => {
    dispatchAndSync({ type: "REMOVE_HEAD_ANNOUNCEMENT", swarmId, feedId, issuerId });
  }, [dispatchAndSync]);

  const ingestRevocationEnvelope = useCallback(
    (record: SwarmRevocationEnvelopeRecord): MaybePromise<SwarmRevocationIngestResult> => {
      const result = evaluateRevocationTrustPolicy(
        selectTrustPolicy(stateRef.current, record.swarmId),
        record.envelope,
      );

      const finalizeRevocationIngest = (
        resolved: FindingTrustPolicyDecision,
      ): SwarmRevocationIngestResult => {
        if (!resolved.accepted) {
          return resolved;
        }

        const duplicateDecision = evaluateRevocationSingleRecordDuplicate(
          stateRef.current,
          record,
        );
        if (duplicateDecision.kind === "reject") {
          return {
            accepted: false,
            reason: duplicateDecision.reason,
          };
        }
        if (duplicateDecision.kind === "append") {
          dispatchAndSync({ type: "INGEST_REVOCATION_ENVELOPE", record });
        }

        return { accepted: true };
      };

      if (isPromiseLike(result)) {
        return result.then(finalizeRevocationIngest);
      }

      return finalizeRevocationIngest(result);
    },
    [dispatchAndSync],
  );

  const getFindingEnvelope = useCallback(
    (swarmId: string, feedId: string, issuerId: string, findingId: string) =>
      selectLatestFindingEnvelope(state, swarmId, feedId, findingId, issuerId),
    [state.findingEnvelopes],
  );

  const resolveFindingReference = useCallback(
    (swarmId: string, feedId: string, issuerId: string, findingId: string) =>
      resolveSwarmFindingReference(state, swarmId, feedId, findingId, issuerId),
    [state],
  );

  const listFindingEnvelopesForSwarm = useCallback(
    (swarmId: string) =>
      state.findingEnvelopes
        .filter((record) => record.swarmId === swarmId)
        .map((record) => record.envelope),
    [state.findingEnvelopes],
  );

  const listFindingEnvelopesForFeed = useCallback(
    (swarmId: string, feedId: string) =>
      state.findingEnvelopes
        .filter((record) => record.swarmId === swarmId && record.envelope.feedId === feedId)
        .map((record) => record.envelope),
    [state.findingEnvelopes],
  );

  const getHeadAnnouncement = useCallback(
    (swarmId: string, feedId: string, issuerId: string) =>
      state.headAnnouncements.find(
        (record) => matchesHeadRecord(record, swarmId, feedId, issuerId, FINDING_HEAD_LANE),
      )?.announcement,
    [state.headAnnouncements],
  );

  const listHeadAnnouncementsForSwarm = useCallback(
    (swarmId: string) =>
      state.headAnnouncements
        .filter((record) => record.swarmId === swarmId && record.lane === FINDING_HEAD_LANE)
        .map((record) => record.announcement),
    [state.headAnnouncements],
  );

  const listHeadAnnouncementsForFeed = useCallback(
    (swarmId: string, feedId: string) =>
      state.headAnnouncements
        .filter(
          (record) =>
            record.swarmId === swarmId &&
            record.lane === FINDING_HEAD_LANE &&
            record.announcement.feedId === feedId,
        )
        .map((record) => record.announcement),
    [state.headAnnouncements],
  );

  const getLatestFindingSeq = useCallback(
    (swarmId: string, feedId: string) =>
      selectLatestFindingSeq(state, swarmId, feedId),
    [state.findingEnvelopes],
  );

  const getLatestHeadSeq = useCallback(
    (swarmId: string, feedId: string, issuerId: string) =>
      selectLatestHeadSeq(state, swarmId, feedId, issuerId),
    [state.headAnnouncements],
  );

  const getFeedSyncState = useCallback(
    (swarmId: string, feedId: string, issuerId: string) =>
      getSwarmFeedSyncState(state, swarmId, feedId, issuerId),
    [state],
  );

  const deriveReplayRequest = useCallback(
    (swarmId: string, remoteHead: HeadAnnouncement, options?: { maxEntries?: number }) =>
      deriveSwarmReplayRequest(state, swarmId, remoteHead, options),
    [state],
  );

  const ingestReplayBatch = useCallback(
    (
      request: SwarmReplayRequest,
      batch: SwarmReplayBatch,
      receivedAt: number = Date.now(),
    ): MaybePromise<SwarmReplayIngestResult> => {
      const currentState = stateRef.current;
      const trustPolicy = selectTrustPolicy(currentState, request.swarmId);
      const trustEvaluation = evaluateReplayBatchTrustPolicy(trustPolicy, batch);

      const finalizeReplayIngest = ({
        filteredBatch,
        trustRejectedEnvelopes,
      }: {
        filteredBatch: SwarmReplayBatch;
        trustRejectedEnvelopes: SwarmReplayTrustRejectedEnvelope[];
      }): SwarmReplayIngestResult => {
        const { state: nextState, validationResult } = ingestSwarmReplayBatchIntoState(
          stateRef.current,
          request,
          filteredBatch,
          receivedAt,
        );
        dispatchAndSync({
          type: "LOAD",
          state: nextState,
        });
        return {
          validationResult,
          trustRejectedEnvelopes,
        };
      };

      if (isPromiseLike(trustEvaluation)) {
        return trustEvaluation.then(finalizeReplayIngest);
      }

      return finalizeReplayIngest(trustEvaluation);
    },
    [dispatchAndSync],
  );

  const projectedFindingRecords = selectProjectedFindingRecords(state);

  const value: SwarmFeedContextValue = {
    findingEnvelopeRecords: state.findingEnvelopes,
    headAnnouncementRecords: state.headAnnouncements,
    revocationEnvelopeRecords: state.revocationEnvelopes,
    projectedFindingRecords,
    findingEnvelopes: state.findingEnvelopes.map((record) => record.envelope),
    headAnnouncements: state.headAnnouncements
      .filter((record) => record.lane === FINDING_HEAD_LANE)
      .map((record) => record.announcement),
    revocationEnvelopes: state.revocationEnvelopes.map((record) => record.envelope),
    getTrustPolicy,
    setTrustPolicy,
    ingestFindingEnvelope,
    removeFindingEnvelope,
    ingestHeadAnnouncement,
    removeHeadAnnouncement,
    ingestRevocationEnvelope,
    getFindingEnvelope,
    resolveFindingReference,
    listFindingEnvelopesForSwarm,
    listFindingEnvelopesForFeed,
    getHeadAnnouncement,
    listHeadAnnouncementsForSwarm,
    listHeadAnnouncementsForFeed,
    getLatestFindingSeq,
    getLatestHeadSeq,
    getFeedSyncState,
    deriveReplayRequest,
    ingestReplayBatch,
  };

  return <SwarmFeedContext.Provider value={value}>{children}</SwarmFeedContext.Provider>;
}
