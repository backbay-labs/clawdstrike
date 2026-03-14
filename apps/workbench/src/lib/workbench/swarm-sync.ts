import {
  isFindingEnvelope,
  isHeadAnnouncement,
  type FindingEnvelope,
  type HeadAnnouncement,
} from "./swarm-protocol";

export interface SwarmReplayTarget {
  swarmId: string;
  feedId: string;
  issuerId: string;
}

export interface SwarmFeedSyncState extends SwarmReplayTarget {
  localFindingSeq: number | null;
  localMaxFindingSeq: number | null;
  localHeadSeq: number | null;
}

export interface SwarmReplayRequest extends SwarmReplayTarget {
  fromSeq: number;
  toSeq: number;
  limit: number;
  localFindingSeq: number | null;
  localMaxFindingSeq: number | null;
  localHeadSeq: number | null;
  remoteHeadSeq: number;
}

export interface SwarmReplayPlan extends SwarmFeedSyncState {
  remoteHeadSeq: number;
  missingFromSeq: number | null;
  missingToSeq: number | null;
  missingCount: number;
  request: SwarmReplayRequest | null;
}

export interface SwarmReplayBatch {
  envelopes: FindingEnvelope[];
  headAnnouncement?: HeadAnnouncement;
}

export interface SwarmReplayProgress {
  contiguousSeq: number | null;
  highestSeenSeq: number | null;
}

export type SwarmReplayRejectionReason =
  | "invalid_head"
  | "target_mismatch"
  | "stale_seq"
  | "duplicate_seq"
  | "out_of_range"
  | "gap_incomplete";

export interface SwarmReplayRejectedEnvelope {
  envelope: FindingEnvelope;
  reason: SwarmReplayRejectionReason;
}

export interface SwarmReplayRejectedHeadAnnouncement {
  announcement: HeadAnnouncement;
  reason: SwarmReplayRejectionReason;
}

export interface ValidateSwarmReplayBatchInput {
  request: SwarmReplayRequest;
  batch: SwarmReplayBatch;
  existingSeqs?: Iterable<number>;
  currentHeadSeq?: number | null;
}

export interface SwarmReplayValidationResult {
  acceptedEnvelopes: FindingEnvelope[];
  rejectedEnvelopes: SwarmReplayRejectedEnvelope[];
  appliedHeadAnnouncement: HeadAnnouncement | null;
  rejectedHeadAnnouncement: SwarmReplayRejectedHeadAnnouncement | null;
  latestFindingSeq: number | null;
  highestSeenFindingSeq: number | null;
  latestHeadSeq: number | null;
}

interface PlanSwarmReplayInput extends SwarmFeedSyncState {
  remoteHeadSeq: number;
  maxEntries?: number;
}

function isValidSeq(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function normalizeNullableSeq(value: number | null | undefined): number | null {
  return isValidSeq(value) ? value : null;
}

function assertSeq(value: number, label: string): number {
  if (!isValidSeq(value)) {
    throw new TypeError(`${label} must be a safe non-negative integer`);
  }
  return value;
}

function assertPositiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a safe positive integer`);
  }
  return value;
}

function toContiguousNullableSeq(value: number): number | null {
  return value > 0 ? value : null;
}

function matchesReplayTarget(
  request: SwarmReplayTarget,
  payload: Pick<FindingEnvelope, "feedId" | "issuerId"> | Pick<HeadAnnouncement, "feedId" | "issuerId">,
): boolean {
  return payload.feedId === request.feedId && payload.issuerId === request.issuerId;
}

export function summarizeSwarmReplayProgress(seqs: Iterable<number>): SwarmReplayProgress {
  const seenSeqs = new Set<number>();
  let highestSeenSeq: number | null = null;

  for (const seq of seqs) {
    if (!isValidSeq(seq)) {
      continue;
    }
    seenSeqs.add(seq);
    highestSeenSeq = highestSeenSeq === null ? seq : Math.max(highestSeenSeq, seq);
  }

  let contiguousTip = 0;
  while (seenSeqs.has(contiguousTip + 1)) {
    contiguousTip++;
  }

  return {
    contiguousSeq: toContiguousNullableSeq(contiguousTip),
    highestSeenSeq,
  };
}

export function planSwarmReplay(input: PlanSwarmReplayInput): SwarmReplayPlan {
  const localFindingSeq = normalizeNullableSeq(input.localFindingSeq);
  const localMaxFindingSeq =
    normalizeNullableSeq(input.localMaxFindingSeq) ?? localFindingSeq;
  const localHeadSeq = normalizeNullableSeq(input.localHeadSeq);
  const remoteHeadSeq = assertSeq(input.remoteHeadSeq, "remoteHeadSeq");
  const effectiveLocalFindingSeq = localFindingSeq ?? 0;

  if (remoteHeadSeq <= effectiveLocalFindingSeq) {
    return {
      swarmId: input.swarmId,
      feedId: input.feedId,
      issuerId: input.issuerId,
      localFindingSeq,
      localMaxFindingSeq,
      localHeadSeq,
      remoteHeadSeq,
      missingFromSeq: null,
      missingToSeq: null,
      missingCount: 0,
      request: null,
    };
  }

  const missingFromSeq = effectiveLocalFindingSeq + 1;
  const missingCount = remoteHeadSeq - effectiveLocalFindingSeq;
  const limit =
    input.maxEntries === undefined
      ? missingCount
      : Math.min(assertPositiveInteger(input.maxEntries, "maxEntries"), missingCount);
  const missingToSeq = Math.min(remoteHeadSeq, missingFromSeq + limit - 1);

  return {
    swarmId: input.swarmId,
    feedId: input.feedId,
    issuerId: input.issuerId,
    localFindingSeq,
    localMaxFindingSeq,
    localHeadSeq,
    remoteHeadSeq,
    missingFromSeq,
    missingToSeq,
    missingCount,
    request: {
      swarmId: input.swarmId,
      feedId: input.feedId,
      issuerId: input.issuerId,
      fromSeq: missingFromSeq,
      toSeq: missingToSeq,
      limit,
      localFindingSeq,
      localMaxFindingSeq,
      localHeadSeq,
      remoteHeadSeq,
    },
  };
}

export function validateSwarmReplayBatch(
  input: ValidateSwarmReplayBatchInput,
): SwarmReplayValidationResult {
  const existingSeqs = new Set<number>();
  for (const seq of input.existingSeqs ?? []) {
    if (isValidSeq(seq)) {
      existingSeqs.add(seq);
    }
  }

  const acceptedEnvelopes: FindingEnvelope[] = [];
  const rejectedEnvelopes: SwarmReplayRejectedEnvelope[] = [];
  const seenIncomingSeqs = new Set<number>();

  for (const envelope of input.batch.envelopes) {
    if (!isFindingEnvelope(envelope)) {
      rejectedEnvelopes.push({
        envelope,
        reason: "target_mismatch",
      });
      continue;
    }

    if (!matchesReplayTarget(input.request, envelope)) {
      rejectedEnvelopes.push({
        envelope,
        reason: "target_mismatch",
      });
      continue;
    }

    if (seenIncomingSeqs.has(envelope.feedSeq)) {
      rejectedEnvelopes.push({
        envelope,
        reason: "duplicate_seq",
      });
      continue;
    }

    if (existingSeqs.has(envelope.feedSeq)) {
      rejectedEnvelopes.push({
        envelope,
        reason: "stale_seq",
      });
      continue;
    }

    if (envelope.feedSeq < input.request.fromSeq || envelope.feedSeq > input.request.toSeq) {
      rejectedEnvelopes.push({
        envelope,
        reason: "out_of_range",
      });
      continue;
    }

    seenIncomingSeqs.add(envelope.feedSeq);
    existingSeqs.add(envelope.feedSeq);
    acceptedEnvelopes.push(envelope);
  }

  const progress = summarizeSwarmReplayProgress(existingSeqs);
  const latestFindingSeq =
    progress.contiguousSeq ?? normalizeNullableSeq(input.request.localFindingSeq);
  const highestSeenFindingSeq =
    progress.highestSeenSeq ??
    normalizeNullableSeq(input.request.localMaxFindingSeq) ??
    latestFindingSeq;

  let latestHeadSeq =
    normalizeNullableSeq(input.currentHeadSeq) ?? normalizeNullableSeq(input.request.localHeadSeq);
  let appliedHeadAnnouncement: HeadAnnouncement | null = null;
  let rejectedHeadAnnouncement: SwarmReplayRejectedHeadAnnouncement | null = null;

  if (input.batch.headAnnouncement) {
    const announcement = input.batch.headAnnouncement;
    if (!isHeadAnnouncement(announcement)) {
      rejectedHeadAnnouncement = {
        announcement,
        reason: "invalid_head",
      };
    } else if (!matchesReplayTarget(input.request, announcement)) {
      rejectedHeadAnnouncement = {
        announcement,
        reason: "target_mismatch",
      };
    } else if (announcement.headSeq > input.request.remoteHeadSeq) {
      rejectedHeadAnnouncement = {
        announcement,
        reason: "out_of_range",
      };
    } else if (announcement.headSeq > (latestFindingSeq ?? 0)) {
      rejectedHeadAnnouncement = {
        announcement,
        reason: "gap_incomplete",
      };
    } else if (
      (latestHeadSeq !== null && announcement.headSeq < latestHeadSeq) ||
      (latestFindingSeq !== null && announcement.headSeq < latestFindingSeq)
    ) {
      rejectedHeadAnnouncement = {
        announcement,
        reason: "stale_seq",
      };
    } else {
      appliedHeadAnnouncement = announcement;
      latestHeadSeq = announcement.headSeq;
    }
  }

  return {
    acceptedEnvelopes,
    rejectedEnvelopes,
    appliedHeadAnnouncement,
    rejectedHeadAnnouncement,
    latestFindingSeq,
    highestSeenFindingSeq,
    latestHeadSeq,
  };
}
