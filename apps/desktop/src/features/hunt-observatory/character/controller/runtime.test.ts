import { describe, expect, it } from "vitest";
import {
  createEmptyObservatoryPlayerIntent,
  DEFAULT_OBSERVATORY_PLAYER_CONFIG,
  DEFAULT_OBSERVATORY_PLAYER_SPAWN,
  type ObservatoryPlayerSpawnPoint,
} from "../types";
import {
  createObservatoryPlayerSpawnCommand,
  createObservatoryPlayerStateFromSpawn,
  stepObservatoryPlayerState,
} from "./runtime";

const forwardSpawn: ObservatoryPlayerSpawnPoint = {
  ...DEFAULT_OBSERVATORY_PLAYER_SPAWN,
  id: "forward",
  facingRadians: 0,
};

describe("stepObservatoryPlayerState", () => {
  it("accelerates into a run when sprint is held", () => {
    const previous = createObservatoryPlayerStateFromSpawn(forwardSpawn);
    const result = stepObservatoryPlayerState(
      previous,
      {
        ...createEmptyObservatoryPlayerIntent(),
        moveY: 1,
        sprint: true,
      },
      {
        deltaSeconds: 0.16,
        nowMs: 160,
        body: {
          position: [...forwardSpawn.position],
          velocity: [0, 0, 0],
          grounded: true,
        },
      },
    );

    expect(result.state.activeAction).toBe("run");
    expect(result.state.sprinting).toBe(true);
    expect(result.command.linearVelocity[2]).toBeGreaterThan(DEFAULT_OBSERVATORY_PLAYER_CONFIG.walkSpeed);
  });

  it("maps lateral movement relative to the live chase camera basis", () => {
    const previous = createObservatoryPlayerStateFromSpawn(forwardSpawn);

    const moveLeft = stepObservatoryPlayerState(
      previous,
      {
        ...createEmptyObservatoryPlayerIntent(),
        moveX: -1,
      },
      {
        deltaSeconds: 0.16,
        nowMs: 160,
        cameraYawRadians: Math.PI,
        body: {
          position: [...forwardSpawn.position],
          velocity: [0, 0, 0],
          grounded: true,
        },
      },
    );

    const moveRight = stepObservatoryPlayerState(
      previous,
      {
        ...createEmptyObservatoryPlayerIntent(),
        moveX: 1,
      },
      {
        deltaSeconds: 0.16,
        nowMs: 160,
        cameraYawRadians: Math.PI,
        body: {
          position: [...forwardSpawn.position],
          velocity: [0, 0, 0],
          grounded: true,
        },
      },
    );

    expect(moveLeft.command.linearVelocity[0]).toBeLessThan(0);
    expect(moveRight.command.linearVelocity[0]).toBeGreaterThan(0);
  });

  it("applies jump velocity and leaves the ground on jump intent", () => {
    const previous = createObservatoryPlayerStateFromSpawn(forwardSpawn);
    const result = stepObservatoryPlayerState(
      previous,
      {
        ...createEmptyObservatoryPlayerIntent(),
        jump: true,
      },
      {
        deltaSeconds: 0.016,
        nowMs: 16,
        body: {
          position: [...forwardSpawn.position],
          velocity: [0, 0, 0],
          grounded: true,
        },
      },
    );

    expect(result.state.grounded).toBe(false);
    expect(result.state.activeAction).toBe("jump-start");
    expect(result.command.linearVelocity[1]).toBe(DEFAULT_OBSERVATORY_PLAYER_CONFIG.jumpVelocity);
  });

  it("applies a front-flip boost in the facing direction", () => {
    const previous = createObservatoryPlayerStateFromSpawn(forwardSpawn);
    const jumpStarted = stepObservatoryPlayerState(
      previous,
      {
        ...createEmptyObservatoryPlayerIntent(),
        jump: true,
      },
      {
        deltaSeconds: 0.016,
        nowMs: 16,
        body: {
          position: [...forwardSpawn.position],
          velocity: [0, 0, 0],
          grounded: true,
        },
      },
    ).state;

    const flipped = stepObservatoryPlayerState(
      jumpStarted,
      {
        ...createEmptyObservatoryPlayerIntent(),
        flipFront: true,
      },
      {
        deltaSeconds: 0.016,
        nowMs: 90,
        body: {
          position: [...forwardSpawn.position],
          velocity: [...jumpStarted.velocity],
          grounded: false,
        },
      },
    );

    expect(flipped.state.activeAction).toBe("flip-front");
    expect(flipped.state.activeFlip).toBe("front");
    expect(flipped.command.linearVelocity[2]).toBeGreaterThan(jumpStarted.velocity[2]);
  });

  it("treats a second jump press while airborne as a front flip", () => {
    const previous = createObservatoryPlayerStateFromSpawn(forwardSpawn);
    const jumpStarted = stepObservatoryPlayerState(
      previous,
      {
        ...createEmptyObservatoryPlayerIntent(),
        jump: true,
      },
      {
        deltaSeconds: 0.016,
        nowMs: 16,
        body: {
          position: [...forwardSpawn.position],
          velocity: [0, 0, 0],
          grounded: true,
        },
      },
    ).state;

    const flipped = stepObservatoryPlayerState(
      jumpStarted,
      {
        ...createEmptyObservatoryPlayerIntent(),
        jump: true,
      },
      {
        deltaSeconds: 0.016,
        nowMs: 90,
        body: {
          position: [...forwardSpawn.position],
          velocity: [...jumpStarted.velocity],
          grounded: false,
        },
      },
    );

    expect(flipped.state.activeAction).toBe("flip-front");
    expect(flipped.state.activeFlip).toBe("front");
  });

  it("applies a back-flip boost opposite the facing direction", () => {
    const previous = createObservatoryPlayerStateFromSpawn(forwardSpawn);
    const jumpStarted = stepObservatoryPlayerState(
      previous,
      {
        ...createEmptyObservatoryPlayerIntent(),
        jump: true,
      },
      {
        deltaSeconds: 0.016,
        nowMs: 16,
        body: {
          position: [...forwardSpawn.position],
          velocity: [0, 0, 0],
          grounded: true,
        },
      },
    ).state;

    const flipped = stepObservatoryPlayerState(
      jumpStarted,
      {
        ...createEmptyObservatoryPlayerIntent(),
        flipBack: true,
      },
      {
        deltaSeconds: 0.016,
        nowMs: 90,
        body: {
          position: [...forwardSpawn.position],
          velocity: [...jumpStarted.velocity],
          grounded: false,
        },
      },
    );

    expect(flipped.state.activeAction).toBe("flip-back");
    expect(flipped.state.activeFlip).toBe("back");
    expect(flipped.command.linearVelocity[2]).toBeLessThan(jumpStarted.velocity[2]);
  });
});

describe("createObservatoryPlayerSpawnCommand", () => {
  it("creates an initial idle body command from the spawn point", () => {
    const command = createObservatoryPlayerSpawnCommand();
    expect(command.translation).toEqual(DEFAULT_OBSERVATORY_PLAYER_SPAWN.position);
    expect(command.activeAction).toBe("idle");
  });
});
