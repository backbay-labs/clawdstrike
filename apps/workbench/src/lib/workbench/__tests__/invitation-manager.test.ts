import { describe, expect, it } from "vitest";
import { createOperatorIdentity } from "../operator-crypto";
import {
  createInvitation,
  validateInvitation,
  acceptInvitation,
  verifyAcceptedInvitation,
  isRoleAttenuation,
  serializeInvitation,
  deserializeInvitation,
} from "../invitation-manager";

describe("isRoleAttenuation", () => {
  it("allows same or lower role", () => {
    expect(isRoleAttenuation("admin", "admin")).toBe(true);
    expect(isRoleAttenuation("admin", "contributor")).toBe(true);
    expect(isRoleAttenuation("admin", "observer")).toBe(true);
    expect(isRoleAttenuation("contributor", "contributor")).toBe(true);
    expect(isRoleAttenuation("contributor", "observer")).toBe(true);
  });

  it("rejects escalation", () => {
    expect(isRoleAttenuation("observer", "contributor")).toBe(false);
    expect(isRoleAttenuation("contributor", "admin")).toBe(false);
  });
});

describe("createInvitation", () => {
  it("creates a valid signed invitation", async () => {
    const { identity, secretKeyHex } = await createOperatorIdentity("Alice");
    const signed = await createInvitation({
      inviterIdentity: identity,
      inviterSecretKey: secretKeyHex,
      inviterRole: "admin",
      swarmId: "swm_test123",
      grantedRole: "contributor",
    });

    expect(signed.claims.iss).toBe(identity.fingerprint);
    expect(signed.claims.sub).toBeNull();
    expect(signed.claims.grantedRole).toBe("contributor");
    expect(signed.signature).toBeTruthy();
  });

  it("rejects role escalation", async () => {
    const { identity, secretKeyHex } = await createOperatorIdentity("Bob");
    await expect(
      createInvitation({
        inviterIdentity: identity,
        inviterSecretKey: secretKeyHex,
        inviterRole: "observer",
        swarmId: "swm_test",
        grantedRole: "admin",
      }),
    ).rejects.toThrow("insufficient");
  });

  it("rejects depth exceeding maximum", async () => {
    const { identity, secretKeyHex } =
      await createOperatorIdentity("Charlie");
    await expect(
      createInvitation({
        inviterIdentity: identity,
        inviterSecretKey: secretKeyHex,
        inviterRole: "admin",
        swarmId: "swm_test",
        grantedRole: "observer",
        depth: 5,
      }),
    ).rejects.toThrow("depth");
  });
});

describe("validateInvitation", () => {
  it("validates a fresh invitation", async () => {
    const { identity, secretKeyHex } = await createOperatorIdentity("Dave");
    const signed = await createInvitation({
      inviterIdentity: identity,
      inviterSecretKey: secretKeyHex,
      inviterRole: "admin",
      swarmId: "swm_test",
      grantedRole: "contributor",
    });
    const result = await validateInvitation(signed);
    expect(result.valid).toBe(true);
  });

  it("rejects expired invitation", async () => {
    const { identity, secretKeyHex } = await createOperatorIdentity("Eve");
    const signed = await createInvitation({
      inviterIdentity: identity,
      inviterSecretKey: secretKeyHex,
      inviterRole: "admin",
      swarmId: "swm_test",
      grantedRole: "contributor",
      expiresInMs: -1000, // already expired
    });
    const result = await validateInvitation(signed);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("expired");
  });
});

describe("acceptInvitation", () => {
  it("binds acceptor and produces valid accepted invitation", async () => {
    const inviter = await createOperatorIdentity("Inviter");
    const acceptor = await createOperatorIdentity("Acceptor");

    const signed = await createInvitation({
      inviterIdentity: inviter.identity,
      inviterSecretKey: inviter.secretKeyHex,
      inviterRole: "admin",
      swarmId: "swm_test",
      grantedRole: "contributor",
    });

    const accepted = await acceptInvitation(
      signed,
      acceptor.identity,
      acceptor.secretKeyHex,
    );
    expect(accepted.invitation.claims.sub).toBe(acceptor.identity.publicKey);
    expect(accepted.acceptorPublicKey).toBe(acceptor.identity.publicKey);
    expect(accepted.acceptorSignature).toBeTruthy();
  });

  it("rejects double acceptance", async () => {
    const inviter = await createOperatorIdentity("Inviter2");
    const acceptor1 = await createOperatorIdentity("Acceptor1");
    const acceptor2 = await createOperatorIdentity("Acceptor2");

    const signed = await createInvitation({
      inviterIdentity: inviter.identity,
      inviterSecretKey: inviter.secretKeyHex,
      inviterRole: "admin",
      swarmId: "swm_test",
      grantedRole: "contributor",
    });

    const accepted = await acceptInvitation(
      signed,
      acceptor1.identity,
      acceptor1.secretKeyHex,
    );

    await expect(
      acceptInvitation(
        accepted.invitation,
        acceptor2.identity,
        acceptor2.secretKeyHex,
      ),
    ).rejects.toThrow("already been accepted");
  });
});

describe("verifyAcceptedInvitation", () => {
  it("verifies a properly accepted invitation", async () => {
    const inviter = await createOperatorIdentity("Verifier-Inviter");
    const acceptor = await createOperatorIdentity("Verifier-Acceptor");

    const signed = await createInvitation({
      inviterIdentity: inviter.identity,
      inviterSecretKey: inviter.secretKeyHex,
      inviterRole: "admin",
      swarmId: "swm_test",
      grantedRole: "contributor",
    });

    const accepted = await acceptInvitation(
      signed,
      acceptor.identity,
      acceptor.secretKeyHex,
    );

    const result = await verifyAcceptedInvitation(accepted);
    expect(result.valid).toBe(true);
  });
});

describe("serialization", () => {
  it("round-trips through serialize/deserialize", async () => {
    const { identity, secretKeyHex } =
      await createOperatorIdentity("Serializer");
    const signed = await createInvitation({
      inviterIdentity: identity,
      inviterSecretKey: secretKeyHex,
      inviterRole: "admin",
      swarmId: "swm_test",
      grantedRole: "observer",
    });

    const encoded = serializeInvitation(signed);
    expect(typeof encoded).toBe("string");

    const decoded = deserializeInvitation(encoded);
    expect(decoded.claims.jti).toBe(signed.claims.jti);
    expect(decoded.signature).toBe(signed.signature);
  });
});
