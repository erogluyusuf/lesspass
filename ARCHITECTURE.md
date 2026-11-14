# Zero-Knowledge Passwordless Vault Architecture

This repository extends stateless deterministic password generation with a **Zero-Knowledge Passwordless Vault** across Core Crypto, Backend Relay, and Mobile Hardware Security layers.

## Architectural Layers

| Layer | Package / Path | Cryptographic & Security Guarantees |
| :--- | :--- | :--- |
| **Core Crypto Engine** | `packages/lesspass/src/vault/` | 256-bit cryptographically random `Master Token`, AES-256-GCM key wrapping (`token.ts`), and ephemeral ECDH P-256 device-to-device key exchange (`pairing.ts`). |
| **Zero-Knowledge Relay** | `backend/api/pairing.py` | Stateless Django REST relay holding only public keys and AES-GCM ciphertext with a strict 120s TTL and atomic **burn-after-reading** deletion on delivery. |
| **Mobile Biometric Vault** | `packages/lesspass-mobile/src/vault/` | Seals the 256-bit `Master Token` inside Android KeyStore / iOS Secure Enclave (`SECURE_HARDWARE`, `BIOMETRY_ANY`) so site passwords are derived via biometrics without typing a master password. |

## Verification Pipeline

Every push and pull request to `dev` and `main` executes three isolated CI jobs via `.github/workflows/ci.yml`:
1. **Core Crypto Engine (TypeScript):** 56 unit tests covering deterministic generation, AES-GCM wrapping, and ECDH P-256 pairing.
2. **Zero-Knowledge Relay API (Django):** API lifecycle tests verifying TTL expiration (`410 Gone`), replay rejection (`409 Conflict`), and burn-after-reading deletion (`404 Not Found`).
3. **Mobile Biometric Vault (React Native):** 49 tests validating hardware keystore sealing, biometric unlock gating, and QR pairing approval.
