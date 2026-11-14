import {
  unwrapMasterToken,
  wrapMasterToken,
  WrappedTokenPayload,
} from "./token";

export interface PairingSession {
  keyPair: CryptoKeyPair;
  publicKeyHex: string;
}

export interface PairingTransferPacket {
  senderPublicKeyHex: string;
  wrappedMasterToken: WrappedTokenPayload;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string length");
  }
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

async function deriveSharedAesKeyHex(
  privateKey: CryptoKey,
  peerPublicKeyHex: string,
): Promise<string> {
  const peerPublicKeyRaw = hexToBytes(peerPublicKeyHex);
  const peerPublicKey = await globalThis.crypto.subtle.importKey(
    "raw",
    peerPublicKeyRaw,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );

  const sharedSecretBits = await globalThis.crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    256,
  );

  return bytesToHex(new Uint8Array(sharedSecretBits));
}

/**
 * Step 1 (New Device): Generates an ephemeral ECDH P-256 keypair.
 * The exported `publicKeyHex` is rendered as a QR code on the new device's screen.
 */
export async function createPairingSession(): Promise<PairingSession> {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );

  const exportedPublicKey = await globalThis.crypto.subtle.exportKey(
    "raw",
    keyPair.publicKey,
  );

  return {
    keyPair,
    publicKeyHex: bytesToHex(new Uint8Array(exportedPublicKey)),
  };
}

/**
 * Step 2 (Trusted Device): Scans the new device's QR public key, derives a shared
 * 256-bit AES secret, and wraps the unlocked Master Token for zero-knowledge transfer.
 */
export async function approvePairingRequest(
  scannedPublicKeyHex: string,
  masterToken: string,
): Promise<PairingTransferPacket> {
  const senderSession = await createPairingSession();
  const sharedAesKeyHex = await deriveSharedAesKeyHex(
    senderSession.keyPair.privateKey,
    scannedPublicKeyHex,
  );

  const wrappedMasterToken = await wrapMasterToken(
    masterToken,
    sharedAesKeyHex,
  );

  return {
    senderPublicKeyHex: senderSession.publicKeyHex,
    wrappedMasterToken,
  };
}

/**
 * Step 3 (New Device): Receives the transfer packet, derives the identical shared
 * 256-bit AES secret using its ephemeral private key, and unwraps the Master Token.
 */
export async function completePairingSession(
  session: PairingSession,
  packet: PairingTransferPacket,
): Promise<string> {
  const sharedAesKeyHex = await deriveSharedAesKeyHex(
    session.keyPair.privateKey,
    packet.senderPublicKeyHex,
  );

  return unwrapMasterToken(packet.wrappedMasterToken, sharedAesKeyHex);
}
