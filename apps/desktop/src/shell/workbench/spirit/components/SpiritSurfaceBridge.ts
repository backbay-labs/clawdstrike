export type SpiritChamberRequestSource =
  | "create"
  | "dock-flyout"
  | "smart-bucket"
  | "spirit-console";

export interface SpiritChamberRequestDetail {
  huntId: string;
  source: SpiritChamberRequestSource;
}

export interface SpiritPinRequestDetail {
  huntId: string;
  source: Exclude<SpiritChamberRequestSource, "create">;
}

const SPIRIT_CHAMBER_REQUEST_EVENT = "huntronomer:spirit-chamber-request";
const SPIRIT_PIN_REQUEST_EVENT = "huntronomer:spirit-pin-request";

function hasWindow(): boolean {
  return typeof window !== "undefined";
}

export function requestSpiritChamber(detail: SpiritChamberRequestDetail): void {
  if (!hasWindow()) return;
  window.dispatchEvent(
    new CustomEvent<SpiritChamberRequestDetail>(SPIRIT_CHAMBER_REQUEST_EVENT, {
      detail,
    }),
  );
}

export function requestSpiritPin(detail: SpiritPinRequestDetail): void {
  if (!hasWindow()) return;
  window.dispatchEvent(
    new CustomEvent<SpiritPinRequestDetail>(SPIRIT_PIN_REQUEST_EVENT, {
      detail,
    }),
  );
}

export function subscribeToSpiritChamberRequests(
  onRequest: (detail: SpiritChamberRequestDetail) => void,
): () => void {
  if (!hasWindow()) return () => {};
  const handler = (event: Event) => {
    onRequest((event as CustomEvent<SpiritChamberRequestDetail>).detail);
  };
  window.addEventListener(SPIRIT_CHAMBER_REQUEST_EVENT, handler);
  return () => window.removeEventListener(SPIRIT_CHAMBER_REQUEST_EVENT, handler);
}

export function subscribeToSpiritPinRequests(
  onRequest: (detail: SpiritPinRequestDetail) => void,
): () => void {
  if (!hasWindow()) return () => {};
  const handler = (event: Event) => {
    onRequest((event as CustomEvent<SpiritPinRequestDetail>).detail);
  };
  window.addEventListener(SPIRIT_PIN_REQUEST_EVENT, handler);
  return () => window.removeEventListener(SPIRIT_PIN_REQUEST_EVENT, handler);
}
