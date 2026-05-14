export type SpiritKind = "sentinel" | "oracle" | "witness" | "specter";

export type SpiritMood = "idle" | "active" | "alert" | "dormant";

export interface SpiritState {
  kind: SpiritKind | null; // null = no spirit bound
  mood: SpiritMood;
  fieldStrength: number; // 0.0–1.0; 0 = unbound, no CSS stain
  accentColor: string | null; // hex color string e.g. "#d4a84b"; null when unbound
  actions: {
    bindSpirit: (kind: SpiritKind) => void;
    unbindSpirit: () => void;
    setMood: (mood: SpiritMood) => void;
    setFieldStrength: (strength: number) => void;
  };
}
