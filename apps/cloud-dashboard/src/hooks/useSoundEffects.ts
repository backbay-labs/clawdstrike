import { useEffect, useRef } from "react";
import type { SSEEvent } from "./useSSE";

let audioCtx: AudioContext | null = null;

function getAudioContext(): AudioContext | null {
  if (audioCtx) return audioCtx;
  try {
    audioCtx = new AudioContext();
  } catch {
    // Web Audio API not available
  }
  return audioCtx;
}

function playTone(
  frequency: number,
  type: OscillatorType,
  durationMs: number,
  endFrequency?: number,
) {
  const ctx = getAudioContext();
  if (!ctx) return;
  if (ctx.state === "suspended") {
    void ctx.resume();
  }

  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.type = type;
  osc.frequency.setValueAtTime(frequency, ctx.currentTime);
  if (endFrequency != null) {
    osc.frequency.linearRampToValueAtTime(endFrequency, ctx.currentTime + durationMs / 1000);
  }
  gain.gain.setValueAtTime(0.15, ctx.currentTime);
  gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + durationMs / 1000);

  osc.connect(gain);
  gain.connect(ctx.destination);
  osc.start();
  osc.stop(ctx.currentTime + durationMs / 1000);
}

function playViolation() {
  playTone(200, "sawtooth", 150);
}

function playAllowed() {
  playTone(800, "sine", 50);
}

function playReconnect() {
  playTone(440, "sine", 300, 880);
}

export function useSoundEffects(events: SSEEvent[], enabled: boolean): void {
  const lastCountRef = useRef(events.length);

  useEffect(() => {
    if (!enabled) {
      lastCountRef.current = events.length;
      return;
    }

    const prevCount = lastCountRef.current;
    const newCount = events.length;

    if (newCount <= prevCount) {
      lastCountRef.current = newCount;
      return;
    }

    // Events are prepended (newest first), so new events are at indices 0..(newCount-prevCount-1)
    const newEvents = events.slice(0, newCount - prevCount);

    for (const evt of newEvents) {
      if (evt.event_type === "session_posture_transition" || evt.event_type === "policy_updated") {
        playReconnect();
      } else if (evt.allowed === false) {
        playViolation();
      } else if (evt.allowed === true) {
        playAllowed();
      }
    }

    lastCountRef.current = newCount;
  }, [events, enabled]);
}
