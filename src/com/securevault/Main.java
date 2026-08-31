package com.securevault;

import com.securevault.crypto.*;
import com.securevault.util.FileUtil;

import java.io.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * SecureVault CLI
 *
 * Modes:
 *  genkeys   <privOut> <pubOut>
 *  encrypt   <inFile> <outFile> <password>          (password-based, AES-256-GCM + permutation layer)
 *  decrypt   <inFile> <outFile> <password>
 *  encrypt-rsa <inFile> <outFile> <publicKeyFile>   (hybrid: RSA-wrapped random AES key)
 *  decrypt-rsa <inFile> <outFile> <privateKeyFile>
 *  sign      <inFile> <sigOutFile> <privateKeyFile>
 *  verify    <inFile> <sigFile> <publicKeyFile>
 *  demo                                              (runs a full self-test, no args needed)
 */
public class Main {

    private static final byte[] MAGIC = "SVLT1".getBytes();
    private static final int MODE_PASSWORD = 1;
    private static final int MODE_RSA = 2;

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            return;
        }

        String cmd = args[0];
        switch (cmd) {
            case "genkeys":
                requireArgs(args, 3, "genkeys <privOut> <pubOut>");
                genKeys(args[1], args[2]);
                break;
            case "encrypt":
                requireArgs(args, 4, "encrypt <inFile> <outFile> <password>");
                encryptPassword(args[1], args[2], args[3].toCharArray());
                break;
            case "decrypt":
                requireArgs(args, 4, "decrypt <inFile> <outFile> <password>");
                decryptPassword(args[1], args[2], args[3].toCharArray());
                break;
            case "encrypt-rsa":
                requireArgs(args, 4, "encrypt-rsa <inFile> <outFile> <publicKeyFile>");
                encryptRsa(args[1], args[2], args[3]);
                break;
            case "decrypt-rsa":
                requireArgs(args, 4, "decrypt-rsa <inFile> <outFile> <privateKeyFile>");
                decryptRsa(args[1], args[2], args[3]);
                break;
            case "sign":
                requireArgs(args, 4, "sign <inFile> <sigOutFile> <privateKeyFile>");
                sign(args[1], args[2], args[3]);
                break;
            case "verify":
                requireArgs(args, 4, "verify <inFile> <sigFile> <publicKeyFile>");
                verify(args[1], args[2], args[3]);
                break;
            case "demo":
                runDemo();
                break;
            default:
                printUsage();
        }
    }

    // ---------- password-based mode ----------

    private static void encryptPassword(String inFile, String outFile, char[] password) throws Exception {
        byte[] plaintext = FileUtil.readAll(inFile);
        byte[] salt = KeyDerivation.generateSalt();
        byte[] aesKey = KeyDerivation.deriveKey(password, salt);

        byte[] permuted = PermutationLayer.permute(plaintext, aesKey);
        byte[] iv = AESCipherUtil.generateIv();
        byte[] ciphertext = AESCipherUtil.encrypt(permuted, aesKey, iv);

        try (DataOutputStream out = FileUtil.open(outFile)) {
            out.write(MAGIC);
            out.writeByte(MODE_PASSWORD);
            out.writeInt(salt.length);
            out.write(salt);
            out.writeInt(iv.length);
            out.write(iv);
            out.writeInt(ciphertext.length);
            out.write(ciphertext);
        }
        Arrays.fill(aesKey, (byte) 0);
        System.out.println("Encrypted -> " + outFile);
    }

    private static void decryptPassword(String inFile, String outFile, char[] password) throws Exception {
        try (DataInputStream in = FileUtil.openIn(inFile)) {
            checkMagic(in);
            int mode = in.readByte();
            if (mode != MODE_PASSWORD) throw new IOException("File is not password-mode encrypted.");

            byte[] salt = readBlock(in);
            byte[] iv = readBlock(in);
            byte[] ciphertext = readBlock(in);

            byte[] aesKey = KeyDerivation.deriveKey(password, salt);
            byte[] permuted;
            try {
                permuted = AESCipherUtil.decrypt(ciphertext, aesKey, iv);
            } catch (Exception e) {
                throw new SecurityException("Decryption failed: wrong password or corrupted/tampered file.", e);
            }
            byte[] plaintext = PermutationLayer.unpermute(permuted, aesKey);

            FileUtil.writeAll(outFile, plaintext);
            Arrays.fill(aesKey, (byte) 0);
            System.out.println("Decrypted -> " + outFile);
        }
    }

    // ---------- RSA hybrid mode ----------

    private static void genKeys(String privOut, String pubOut) throws Exception {
        KeyPair kp = RSAUtil.generateKeyPair();
        RSAUtil.savePrivateKey(kp.getPrivate(), privOut);
        RSAUtil.savePublicKey(kp.getPublic(), pubOut);
        System.out.println("Keys written: " + privOut + " , " + pubOut);
    }

    private static void encryptRsa(String inFile, String outFile, String pubKeyFile) throws Exception {
        byte[] plaintext = FileUtil.readAll(inFile);
        PublicKey pub = RSAUtil.loadPublicKey(pubKeyFile);

        byte[] aesKey = new byte[32]; // random 256-bit session key
        new java.security.SecureRandom().nextBytes(aesKey);

        byte[] permuted = PermutationLayer.permute(plaintext, aesKey);
        byte[] iv = AESCipherUtil.generateIv();
        byte[] ciphertext = AESCipherUtil.encrypt(permuted, aesKey, iv);
        byte[] wrappedKey = RSAUtil.wrapKey(aesKey, pub);

        try (DataOutputStream out = FileUtil.open(outFile)) {
            out.write(MAGIC);
            out.writeByte(MODE_RSA);
            out.writeInt(wrappedKey.length);
            out.write(wrappedKey);
            out.writeInt(iv.length);
            out.write(iv);
            out.writeInt(ciphertext.length);
            out.write(ciphertext);
        }
        Arrays.fill(aesKey, (byte) 0);
        System.out.println("Encrypted (RSA hybrid) -> " + outFile);
    }

    private static void decryptRsa(String inFile, String outFile, String privKeyFile) throws Exception {
        try (DataInputStream in = FileUtil.openIn(inFile)) {
            checkMagic(in);
            int mode = in.readByte();
            if (mode != MODE_RSA) throw new IOException("File is not RSA-mode encrypted.");

            byte[] wrappedKey = readBlock(in);
            byte[] iv = readBlock(in);
            byte[] ciphertext = readBlock(in);

            PrivateKey priv = RSAUtil.loadPrivateKey(privKeyFile);
            byte[] aesKey = RSAUtil.unwrapKey(wrappedKey, priv);

            byte[] permuted;
            try {
                permuted = AESCipherUtil.decrypt(ciphertext, aesKey, iv);
            } catch (Exception e) {
                throw new SecurityException("Decryption failed: wrong key or corrupted/tampered file.", e);
            }
            byte[] plaintext = PermutationLayer.unpermute(permuted, aesKey);

            FileUtil.writeAll(outFile, plaintext);
            Arrays.fill(aesKey, (byte) 0);
            System.out.println("Decrypted -> " + outFile);
        }
    }

    // ---------- signatures ----------

    private static void sign(String inFile, String sigOut, String privKeyFile) throws Exception {
        byte[] data = FileUtil.readAll(inFile);
        PrivateKey priv = RSAUtil.loadPrivateKey(privKeyFile);
        byte[] signature = RSAUtil.sign(data, priv);
        FileUtil.writeAll(sigOut, java.util.Base64.getEncoder().encode(signature));
        System.out.println("Signature written -> " + sigOut);
    }

    private static void verify(String inFile, String sigFile, String pubKeyFile) throws Exception {
        byte[] data = FileUtil.readAll(inFile);
        byte[] signature = java.util.Base64.getDecoder().decode(FileUtil.readAll(sigFile));
        PublicKey pub = RSAUtil.loadPublicKey(pubKeyFile);
        boolean valid = RSAUtil.verify(data, signature, pub);
        System.out.println(valid ? "VALID signature." : "INVALID signature (file was modified or wrong key).");
    }

    // ---------- helpers ----------

    private static void checkMagic(DataInputStream in) throws IOException {
        byte[] magic = new byte[MAGIC.length];
        in.readFully(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IOException("Not a valid SecureVault file.");
        }
    }

    private static byte[] readBlock(DataInputStream in) throws IOException {
        int len = in.readInt();
        byte[] data = new byte[len];
        in.readFully(data);
        return data;
    }

    private static void requireArgs(String[] args, int count, String usage) {
        if (args.length < count) {
            System.out.println("Usage: " + usage);
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("SecureVault - layered Java encryption CLI\n");
        System.out.println("  genkeys     <privOut> <pubOut>");
        System.out.println("  encrypt     <inFile> <outFile> <password>");
        System.out.println("  decrypt     <inFile> <outFile> <password>");
        System.out.println("  encrypt-rsa <inFile> <outFile> <publicKeyFile>");
        System.out.println("  decrypt-rsa <inFile> <outFile> <privateKeyFile>");
        System.out.println("  sign        <inFile> <sigOutFile> <privateKeyFile>");
        System.out.println("  verify      <inFile> <sigFile> <publicKeyFile>");
        System.out.println("  demo        (runs a full self-test)");
    }

    // ---------- self-test / demo ----------

    private static void runDemo() throws Exception {
        System.out.println("=== SecureVault self-test ===\n");

        // 1. Password mode round trip
        FileUtil.writeAll("demo_plain.txt", "Hello from SecureVault! This is a resume project. 12345".getBytes());
        encryptPassword("demo_plain.txt", "demo.vault", "correct-horse-battery-staple".toCharArray());
        decryptPassword("demo.vault", "demo_decrypted.txt", "correct-horse-battery-staple".toCharArray());
        boolean match = Arrays.equals(FileUtil.readAll("demo_plain.txt"), FileUtil.readAll("demo_decrypted.txt"));
        System.out.println("[password mode] round trip match: " + match);

        // 2. Wrong password should fail
        try {
            decryptPassword("demo.vault", "demo_wrong.txt", "wrong-password".toCharArray());
            System.out.println("[password mode] wrong password test: FAILED (should have thrown)");
        } catch (SecurityException e) {
            System.out.println("[password mode] wrong password correctly rejected: true");
        }

        // 3. RSA hybrid mode round trip
        genKeys("demo_priv.key", "demo_pub.key");
        encryptRsa("demo_plain.txt", "demo_rsa.vault", "demo_pub.key");
        decryptRsa("demo_rsa.vault", "demo_rsa_decrypted.txt", "demo_priv.key");
        boolean rsaMatch = Arrays.equals(FileUtil.readAll("demo_plain.txt"), FileUtil.readAll("demo_rsa_decrypted.txt"));
        System.out.println("[RSA hybrid mode] round trip match: " + rsaMatch);

        // 4. Tamper detection: flip a byte in the ciphertext file and confirm GCM rejects it
        byte[] tampered = FileUtil.readAll("demo.vault");
        tampered[tampered.length - 1] ^= 0x01; // flip last bit of the file
        FileUtil.writeAll("demo_tampered.vault", tampered);
        try {
            decryptPassword("demo_tampered.vault", "should_not_exist.txt", "correct-horse-battery-staple".toCharArray());
            System.out.println("[tamper detection] FAILED (should have thrown)");
        } catch (SecurityException e) {
            System.out.println("[tamper detection] tampering correctly detected: true");
        }

        // 5. Digital signature
        sign("demo_plain.txt", "demo.sig", "demo_priv.key");
        verify("demo_plain.txt", "demo.sig", "demo_pub.key");

        System.out.println("\n=== Self-test complete ===");
    }
}
