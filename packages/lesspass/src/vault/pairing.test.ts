import { describe, expect, test } from "vitest";
import {
  approvePairingRequest,
  completePairingSession,
  createPairingSession,
} from "./pairing";
import { generateMasterToken } from "./token";

describe("ECDH P-256 Passwordless QR Device Pairing", () => {
  test("full device-to-device QR pairing transfers Master Token securely", async () => {
    const originalMasterToken = generateMasterToken();

    // 1. New device generates QR code payload
    const newDeviceSession = await createPairingSession();
    expect(newDeviceSession.publicKeyHex.length).toBeGreaterThan(64);

    // 2. Trusted device scans QR and wraps its Master Token
    const transferPacket = await approvePairingRequest(
      newDeviceSession.publicKeyHex,
      originalMasterToken,
    );

    // 3. New device receives packet and unwraps Master Token
    const transferredToken = await completePairingSession(
      newDeviceSession,
      transferPacket,
    );

    expect(transferredToken).toBe(originalMasterToken);
  });

  test("unauthorized device with different ephemeral key cannot decrypt packet", async () => {
    const originalMasterToken = generateMasterToken();

    const legitimateNewDevice = await createPairingSession();
    const attackerDevice = await createPairingSession();

    const transferPacket = await approvePairingRequest(
      legitimateNewDevice.publicKeyHex,
      originalMasterToken,
    );

    await expect(
      completePairingSession(attackerDevice, transferPacket),
    ).rejects.toThrow();
  });
});
