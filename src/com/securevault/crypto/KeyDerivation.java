package com.securevault.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

/**
 * Turns a human password into a 256-bit AES key using PBKDF2-HMAC-SHA256
 * with a random salt and a high iteration count. This is what stands
 * between "password123" and an attacker's GPU cluster.
 */
public class KeyDerivation {

    public static final int SALT_LENGTH_BYTES = 16;
    public static final int ITERATIONS = 200_000; // deliberately slow, tune per hardware
    public static final int KEY_LENGTH_BITS = 256;

    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    public static byte[] deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = factory.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return key;
    }
}
