// Ported verbatim from huntronomer apps/desktop/src/features/hunt-observatory/character/controller/useObservatoryPlayerRuntime.ts
// Import remapped: ../types → ../types (character types), ./runtime → ./runtime

import { useCallback, useMemo, useRef, useState } from "react";
import {
  DEFAULT_OBSERVATORY_PLAYER_SPAWN,
  mergeObservatoryPlayerConfig,
  type ObservatoryPlayerBodySnapshot,
  type ObservatoryPlayerCommand,
  type ObservatoryPlayerControllerOptions,
  type ObservatoryPlayerRuntimeApi,
  type ObservatoryPlayerSpawnPoint,
  type ObservatoryPlayerStepContext,
  type ObservatoryPlayerIntent,
} from "../types";
import {
  createObservatoryPlayerSpawnCommand,
  createObservatoryPlayerStateFromSpawn,
  stepObservatoryPlayerState,
} from "./runtime";

function createBodySnapshotFallback(api: ObservatoryPlayerRuntimeApi["state"]): ObservatoryPlayerBodySnapshot {
  return {
    position: [...api.position],
    velocity: [...api.velocity],
    grounded: api.grounded,
    stationId: api.stationId,
  };
}

export function useObservatoryPlayerRuntime(
  options: ObservatoryPlayerControllerOptions = {},
): ObservatoryPlayerRuntimeApi {
  const config = useMemo(() => mergeObservatoryPlayerConfig(options.config), [options.config]);
  const spawn = options.spawn ?? DEFAULT_OBSERVATORY_PLAYER_SPAWN;
  const bodyAdapter = options.bodyAdapter ?? null;
  const [state, setState] = useState(() => createObservatoryPlayerStateFromSpawn(spawn));
  const [lastCommand, setLastCommand] = useState<ObservatoryPlayerCommand | null>(() =>
    createObservatoryPlayerSpawnCommand(spawn),
  );
  const stateRef = useRef(state);
  const lastCommandRef = useRef(lastCommand);

  const commit = useCallback((nextState: typeof state, nextCommand: ObservatoryPlayerCommand | null) => {
    stateRef.current = nextState;
    setState(nextState);
    if (nextCommand) {
      lastCommandRef.current = nextCommand;
      setLastCommand(nextCommand);
      bodyAdapter?.applyCommand?.(nextCommand);
    }
  }, [bodyAdapter]);

  const reset = useCallback((nextSpawn?: ObservatoryPlayerSpawnPoint | null) => {
    const resolvedSpawn = nextSpawn ?? spawn;
    const nextState = createObservatoryPlayerStateFromSpawn(resolvedSpawn);
    const nextCommand = createObservatoryPlayerSpawnCommand(resolvedSpawn);
    commit(nextState, nextCommand);
    return nextState;
  }, [commit, spawn]);

  const step = useCallback((intent: ObservatoryPlayerIntent, context: ObservatoryPlayerStepContext) => {
    const body =
      context.body
      ?? bodyAdapter?.readSnapshot?.()
      ?? createBodySnapshotFallback(stateRef.current);
    const result = stepObservatoryPlayerState(
      stateRef.current,
      intent,
      { ...context, body },
      config,
    );
    commit(result.state, result.command);
    return result;
  }, [bodyAdapter, commit, config]);

  return {
    state,
    config,
    spawn,
    lastCommand,
    reset,
    step,
  };
}
