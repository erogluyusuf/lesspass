import * as Keychain from "react-native-keychain";
import {
  generateMasterToken,
  generatePassword,
  PasswordProfile,
  approvePairingRequest,
  PairingTransferPacket,
} from "lesspass";

const VAULT_SERVICE = "com.lesspass.vault.master_token";
const VAULT_ACCOUNT = "primary_vault_owner";

export interface BiometricPromptOptions {
  title?: string;
  subtitle?: string;
  cancel?: string;
}

/**
 * Checks whether the device supports hardware-backed biometric storage
 * (Android KeyStore / StrongBox or iOS Secure Enclave).
 */
export async function isHardwareVaultAvailable(): Promise<boolean> {
  const biometryType = await Keychain.getSupportedBiometryType();
  return biometryType !== null;
}

/**
 * Generates or stores a 256-bit Master Token inside the device's hardware
 * keystore, bound to biometric authentication.
 */
export async function initializeHardwareVault(
  existingMasterToken?: string,
): Promise<string> {
  const token = existingMasterToken ?? generateMasterToken();

  const saved = await Keychain.setGenericPassword(VAULT_ACCOUNT, token, {
    service: VAULT_SERVICE,
    accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_ANY,
    accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE,
  });

  if (!saved) {
    throw new Error("Failed to seal Master Token in hardware keystore");
  }

  return token;
}

/**
 * Prompts the user for fingerprint/FaceID and retrieves the Master Token
 * directly from the hardware secure element.
 */
export async function unlockMasterTokenWithBiometrics(
  prompt?: BiometricPromptOptions,
): Promise<string> {
  const credentials = await Keychain.getGenericPassword({
    service: VAULT_SERVICE,
    authenticationPrompt: {
      title: prompt?.title ?? "Kasayı Aç",
      subtitle:
        prompt?.subtitle ??
        "Donanım anahtarını çözmek için biyometrik doğrulama yapın",
      cancel: prompt?.cancel ?? "İptal",
    },
  });

  if (!credentials || !credentials.password) {
    throw new Error("Biometric authentication failed or vault is empty");
  }

  return credentials.password;
}

/**
 * Passwordless flow: authenticates via biometrics and derives a deterministic
 * site password using the hardware-sealed Master Token.
 */
export async function deriveSitePasswordWithBiometrics(
  profile: PasswordProfile,
  prompt?: BiometricPromptOptions,
): Promise<string> {
  const masterToken = await unlockMasterTokenWithBiometrics(prompt);
  return generatePassword(profile, masterToken);
}

/**
 * Approves a new device's QR pairing request by unlocking the Master Token
 * via biometrics and wrapping it with the peer's ephemeral ECDH P-256 public key.
 */
export async function approveDevicePairingWithBiometrics(
  scannedPublicKeyHex: string,
  prompt?: BiometricPromptOptions,
): Promise<PairingTransferPacket> {
  const masterToken = await unlockMasterTokenWithBiometrics(prompt);
  return approvePairingRequest(scannedPublicKeyHex, masterToken);
}

/**
 * Wipes the Master Token from the hardware keystore.
 */
export async function wipeHardwareVault(): Promise<boolean> {
  return Keychain.resetGenericPassword({ service: VAULT_SERVICE });
}
