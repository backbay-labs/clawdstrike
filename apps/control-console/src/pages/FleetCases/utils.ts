export function numberText(value: number | undefined): string {
  return value == null ? "-" : String(value);
}

export function byteText(value: number | null | undefined): string {
  return value == null ? "-" : `${value} bytes`;
}

export function formatDateTime(value: string | undefined): string {
  return value ? new Date(value).toLocaleString() : "-";
}
