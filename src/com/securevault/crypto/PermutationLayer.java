package com.securevault.crypto;

import java.security.MessageDigest;
import java.util.Random;

/**
 * A keyed byte-permutation layer applied BEFORE AES-GCM encryption.
 *
 * IMPORTANT / HONEST NOTE: this layer is NOT a replacement for AES and does
 * not add cryptographic strength on its own -- a permutation of bytes is
 * trivially reversible if you know (or brute-force) the key. Its purpose
 * here is defense-in-depth / obfuscation: it means an attacker who somehow
 * defeats or misconfigures the outer AES layer still has to deal with a
 * key-dependent reordering of the data, and it demonstrates you understand
 * how to build reversible, keyed transformations correctly (including the
 * classic bug of getting the inverse permutation wrong).
 *
 * The permutation itself is generated with a Fisher-Yates shuffle driven by
 * a PRNG seeded from a SHA-256 hash of the caller's key material, so the
 * same key always reproduces the same permutation (required for decryption)
 * while different keys produce effectively unrelated permutations.
 */
public class PermutationLayer {

    /** Builds a permutation of indices [0, length) seeded from the given key bytes. */
    private static int[] buildPermutation(byte[] keyMaterial, int length) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(keyMaterial);

        long seed = 0L;
        for (int i = 0; i < 8; i++) {
            seed = (seed << 8) | (hash[i] & 0xFF);
        }

        Random prng = new Random(seed);
        int[] perm = new int[length];
        for (int i = 0; i < length; i++) perm[i] = i;

        // Fisher-Yates shuffle
        for (int i = length - 1; i > 0; i--) {
            int j = prng.nextInt(i + 1);
            int tmp = perm[i];
            perm[i] = perm[j];
            perm[j] = tmp;
        }
        return perm;
    }

    public static byte[] permute(byte[] data, byte[] keyMaterial) throws Exception {
        int[] perm = buildPermutation(keyMaterial, data.length);
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = data[perm[i]];
        }
        return out;
    }

    public static byte[] unpermute(byte[] data, byte[] keyMaterial) throws Exception {
        int[] perm = buildPermutation(keyMaterial, data.length);
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[perm[i]] = data[i];
        }
        return out;
    }
}
