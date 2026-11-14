import { generatePassword, PasswordProfile } from "../index";

export interface WrappedTokenPayload {
  iv: string;
  ciphertext: string;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Generates a cryptographically secure random Master Token (default 256-bit / 32 bytes).
 * Stored inside hardware-backed storage (Android Keystore / iOS Secure Enclave) behind biometrics.
 */
export function generateMasterToken(byteLength = 32): string {
  const randomBytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(randomBytes);
  return bytesToHex(randomBytes);
}

/**
 * Encrypts (wraps) the Master Token using AES-GCM (256-bit) for Zero-Knowledge cloud backup
 * or ephemeral QR device pairing.
 */
export async function wrapMasterToken(
  masterToken: string,
  wrappingKeyHex: string,
): Promise<WrappedTokenPayload> {
  const rawKey = hexToBytes(wrappingKeyHex);
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );

  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);

  const encodedToken = new TextEncoder().encode(masterToken);
  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    encodedToken,
  );

  return {
    iv: bytesToHex(iv),
    ciphertext: bytesToHex(new Uint8Array(encryptedBuffer)),
  };
}

/**
 * Decrypts (unwraps) a wrapped Master Token payload and verifies AES-GCM integrity tag.
 */
export async function unwrapMasterToken(
  payload: WrappedTokenPayload,
  wrappingKeyHex: string,
): Promise<string> {
  const rawKey = hexToBytes(wrappingKeyHex);
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  const iv = hexToBytes(payload.iv);
  const ciphertext = hexToBytes(payload.ciphertext);

  const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    ciphertext,
  );

  return new TextDecoder().decode(decryptedBuffer);
}

/**
 * Derives a deterministic site password from a hardware-unlocked Master Token.
 */
export function generatePasswordFromToken(
  profile: PasswordProfile,
  masterToken: string,
): Promise<string> {
  if (!masterToken || masterToken.trim().length < 32) {
    return Promise.reject(new Error("Master token is missing or insufficient entropy"));
  }
  return generatePassword(profile, masterToken);
}
