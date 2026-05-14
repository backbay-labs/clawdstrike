// apps/workbench/src/features/forensics/types.ts

export type TapeEventKind = "allow" | "deny" | "probe" | "receipt";

export interface TapeEvent {
  id: string;
  timestamp: number;
  kind: TapeEventKind;
  label: string;
  stationId?: string;
}
