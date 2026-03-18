export type SpiritKind =
  | "ember"     // fire/red hue — #e05c3a
  | "tide"      // water/blue hue — #3a8ae0
  | "verdant"   // nature/green hue — #3dbf84
  | "void"      // dark/purple hue — #7a3ae0
  | "neutral";  // gold hue — #d4a84b (default when spirit bound without affinity)

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
