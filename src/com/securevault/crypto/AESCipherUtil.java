package com.securevault.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * AES-256-GCM authenticated encryption.
 * GCM mode gives us confidentiality AND integrity (via the built-in auth tag)
 * in a single pass, which is why it's the industry-standard choice over
 * plain CBC mode.
 */
public class AESCipherUtil {

    public static final int IV_LENGTH_BYTES = 12;      // 96-bit IV, recommended for GCM
    public static final int TAG_LENGTH_BITS = 128;      // 128-bit auth tag

    public static byte[] generateIv() {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static byte[] encrypt(byte[] plaintext, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
        return cipher.doFinal(plaintext); // ciphertext + auth tag appended
    }

    public static byte[] decrypt(byte[] ciphertextWithTag, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
        // Throws AEADBadTagException automatically if data was tampered with
        return cipher.doFinal(ciphertextWithTag);
    }
}
