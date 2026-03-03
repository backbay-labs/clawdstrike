export interface Wallpaper {
  id: string;
  name: string;
  gradient: string;
}

export const WALLPAPERS: Wallpaper[] = [
  {
    id: "default",
    name: "Gold Radial",
    gradient:
      "radial-gradient(ellipse 80% 60% at 50% 40%, rgba(214,177,90,0.04) 0%, transparent 70%), radial-gradient(ellipse at 50% 50%, transparent 40%, rgba(0,0,0,0.4) 100%), #000",
  },
  {
    id: "deep-blue",
    name: "Deep Blue",
    gradient:
      "radial-gradient(ellipse 80% 60% at 50% 40%, rgba(30,64,175,0.06) 0%, transparent 70%), radial-gradient(ellipse at 50% 50%, transparent 40%, rgba(0,0,0,0.5) 100%), #020617",
  },
  {
    id: "emerald",
    name: "Emerald Grid",
    gradient:
      "radial-gradient(ellipse 60% 50% at 30% 60%, rgba(16,185,129,0.04) 0%, transparent 60%), radial-gradient(ellipse 60% 50% at 70% 40%, rgba(16,185,129,0.03) 0%, transparent 60%), #000",
  },
  {
    id: "crimson",
    name: "Crimson Nebula",
    gradient:
      "radial-gradient(ellipse 70% 50% at 40% 50%, rgba(194,59,59,0.05) 0%, transparent 60%), radial-gradient(ellipse at 60% 50%, transparent 30%, rgba(0,0,0,0.5) 100%), #0a0000",
  },
  {
    id: "minimal",
    name: "Minimal Dark",
    gradient: "#000",
  },
  {
    id: "topology",
    name: "Topology Lines",
    gradient: "linear-gradient(180deg, #0a0a0a 0%, #050505 100%)",
  },
  {
    id: "teal-glow",
    name: "Teal Glow",
    gradient:
      "radial-gradient(ellipse 80% 60% at 50% 40%, rgba(47,167,160,0.04) 0%, transparent 70%), #000",
  },
  {
    id: "sunset",
    name: "Sunset Gold",
    gradient:
      "radial-gradient(ellipse 80% 60% at 50% 60%, rgba(214,177,90,0.06) 0%, transparent 50%), radial-gradient(ellipse at 30% 30%, rgba(194,59,59,0.03) 0%, transparent 60%), #000",
  },
];
