import type {
  ActorType,
  OriginDefaultBehavior,
  OriginProvider,
  ProvenanceConfidence,
  SpaceType,
  Visibility,
} from "./types";

export interface OriginOption<T extends string> {
  value: T;
  label: string;
}

export const ORIGIN_PROVIDER_OPTIONS: ReadonlyArray<OriginOption<OriginProvider>> = [
  { value: "slack", label: "Slack" },
  { value: "teams", label: "Teams" },
  { value: "github", label: "GitHub" },
  { value: "jira", label: "Jira" },
  { value: "email", label: "Email" },
  { value: "discord", label: "Discord" },
  { value: "webhook", label: "Webhook" },
  { value: "cli", label: "CLI" },
  { value: "api", label: "API" },
];

export const ORIGIN_SPACE_TYPE_OPTIONS: ReadonlyArray<OriginOption<SpaceType>> = [
  { value: "channel", label: "Channel" },
  { value: "group", label: "Group" },
  { value: "dm", label: "DM" },
  { value: "thread", label: "Thread" },
  { value: "issue", label: "Issue" },
  { value: "ticket", label: "Ticket" },
  { value: "pull_request", label: "Pull Request" },
  { value: "email_thread", label: "Email Thread" },
];

export const ORIGIN_VISIBILITY_OPTIONS: ReadonlyArray<OriginOption<Visibility>> = [
  { value: "private", label: "Private" },
  { value: "internal", label: "Internal" },
  { value: "restricted", label: "Restricted" },
  { value: "public", label: "Public" },
  { value: "external", label: "External" },
  { value: "external_shared", label: "External Shared" },
  { value: "unknown", label: "Unknown" },
];

export const ORIGIN_PROVENANCE_OPTIONS: ReadonlyArray<OriginOption<ProvenanceConfidence>> = [
  { value: "strong", label: "Strong" },
  { value: "medium", label: "Medium" },
  { value: "weak", label: "Weak" },
  { value: "unknown", label: "Unknown" },
];

export const ORIGIN_ACTOR_TYPE_OPTIONS: ReadonlyArray<OriginOption<ActorType>> = [
  { value: "human", label: "Human" },
  { value: "bot", label: "Bot" },
  { value: "service", label: "Service" },
  { value: "unknown", label: "Unknown" },
];

export const ORIGIN_DEFAULT_BEHAVIOR_OPTIONS: ReadonlyArray<
  OriginOption<OriginDefaultBehavior>
> = [
  { value: "deny", label: "Deny" },
  { value: "minimal_profile", label: "Minimal Profile" },
];

export function isCustomOriginChoice<T extends string>(
  value: string | undefined,
  options: ReadonlyArray<OriginOption<T>>,
): boolean {
  return value !== undefined && !options.some((option) => option.value === value);
}
