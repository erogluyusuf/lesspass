import { beforeEach, describe, expect, test, vi } from "vitest";
import * as Keychain from "react-native-keychain";
import {
  approveDevicePairingWithBiometrics,
  deriveSitePasswordWithBiometrics,
  initializeHardwareVault,
  isHardwareVaultAvailable,
  wipeHardwareVault,
} from "./biometricVault";
import { completePairingSession, createPairingSession } from "lesspass";

vi.mock("react-native-keychain", () => {
  let storedSecret: string | null = null;
  let simulateAuthFailure = false;

  return {
    ACCESS_CONTROL: { BIOMETRY_ANY: "BiometryAny" },
    ACCESSIBLE: { WHEN_UNLOCKED_THIS_DEVICE_ONLY: "WhenUnlockedThisDeviceOnly" },
    SECURITY_LEVEL: { SECURE_HARDWARE: "SECURE_HARDWARE" },
    BIOMETRY_TYPE: { FINGERPRINT: "Fingerprint" },
    getSupportedBiometryType: vi.fn(async () => "Fingerprint"),
    setGenericPassword: vi.fn(async (_user: string, password: string) => {
      storedSecret = password;
      return { service: "com.lesspass.vault.master_token", storage: "Keystore" };
    }),
    getGenericPassword: vi.fn(async () => {
      if (simulateAuthFailure || !storedSecret) {
        return false;
      }
      return {
        username: "primary_vault_owner",
        password: storedSecret,
        service: "com.lesspass.vault.master_token",
      };
    }),
    resetGenericPassword: vi.fn(async () => {
      storedSecret = null;
      return true;
    }),
    __setSimulateAuthFailure: (fail: boolean) => {
      simulateAuthFailure = fail;
    },
  };
});

describe("Mobile Biometric Hardware Vault (KeyStore / Secure Enclave)", () => {
  beforeEach(async () => {
    (Keychain as unknown as { __setSimulateAuthFailure: (f: boolean) => void }).__setSimulateAuthFailure(false);
    await wipeHardwareVault();
  });

  test("detects hardware biometry and seals a 256-bit Master Token", async () => {
    expect(await isHardwareVaultAvailable()).toBe(true);

    const token = await initializeHardwareVault();
    expect(token).toHaveLength(64);
    expect(Keychain.setGenericPassword).toHaveBeenCalledWith(
      "primary_vault_owner",
      token,
      expect.objectContaining({
        accessControl: "BiometryAny",
        securityLevel: "SECURE_HARDWARE",
      }),
    );
  });

  test("derives deterministic site password using biometric-unlocked Master Token", async () => {
    await initializeHardwareVault("a".repeat(64));

    const password = await deriveSitePasswordWithBiometrics({
      site: "github.com",
      login: "erogluyusuf",
      lowercase: true,
      uppercase: true,
      digits: true,
      symbols: true,
      length: 16,
      counter: 1,
    });

    expect(password).toHaveLength(16);
  });

  test("blocks password derivation when biometric authentication fails", async () => {
    await initializeHardwareVault("b".repeat(64));
    (Keychain as unknown as { __setSimulateAuthFailure: (f: boolean) => void }).__setSimulateAuthFailure(true);

    await expect(
      deriveSitePasswordWithBiometrics({
        site: "github.com",
        login: "erogluyusuf",
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
        length: 16,
        counter: 1,
      }),
    ).rejects.toThrow("Biometric authentication failed");
  });

  test("approves QR device pairing after biometric check and transfers Master Token", async () => {
    const originalToken = await initializeHardwareVault();
    const newDevice = await createPairingSession();

    const packet = await approveDevicePairingWithBiometrics(
      newDevice.publicKeyHex,
    );
    const transferredToken = await completePairingSession(newDevice, packet);

    expect(transferredToken).toBe(originalToken);
  });
});
