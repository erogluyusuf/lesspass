import { describe, expect, test } from "vitest";
import { defaultPasswordProfile } from "../index";
import {
  generateMasterToken,
  generatePasswordFromToken,
  unwrapMasterToken,
  wrapMasterToken,
} from "./token";

describe("Zero-Knowledge Vault Master Token", () => {
  test("generateMasterToken produces unique 256-bit hex tokens", () => {
    const token1 = generateMasterToken();
    const token2 = generateMasterToken();

    expect(token1).toHaveLength(64);
    expect(token2).toHaveLength(64);
    expect(token1).not.toBe(token2);
    expect(/^[0-9a-f]{64}$/.test(token1)).toBe(true);
  });

  test("wrapMasterToken and unwrapMasterToken roundtrip succeeds with valid key", async () => {
    const masterToken = generateMasterToken();
    const wrappingKey = generateMasterToken();

    const wrapped = await wrapMasterToken(masterToken, wrappingKey);
    expect(wrapped.iv).toHaveLength(24);
    expect(wrapped.ciphertext.length).toBeGreaterThan(0);

    const unwrapped = await unwrapMasterToken(wrapped, wrappingKey);
    expect(unwrapped).toBe(masterToken);
  });

  test("unwrapMasterToken rejects wrong key or tampered ciphertext", async () => {
    const masterToken = generateMasterToken();
    const correctKey = generateMasterToken();
    const wrongKey = generateMasterToken();

    const wrapped = await wrapMasterToken(masterToken, correctKey);

    await expect(unwrapMasterToken(wrapped, wrongKey)).rejects.toThrow();
  });

  test("generatePasswordFromToken derives consistent deterministic passwords", async () => {
    const masterToken =
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    const profile = {
      ...defaultPasswordProfile,
      site: "github.com",
      login: "yusuferoglu1957@gmail.com",
      length: 16,
    };

    const pass1 = await generatePasswordFromToken(profile, masterToken);
    const pass2 = await generatePasswordFromToken(profile, masterToken);

    expect(pass1).toHaveLength(16);
    expect(pass1).toBe(pass2);
  });
});
