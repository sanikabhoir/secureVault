package com.securevault.crypto;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * RSA-2048 for key exchange (wrapping an AES session key) and for
 * digital signatures (SHA256withRSA).
 */
public class RSAUtil {

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    public static void savePublicKey(PublicKey key, String path) throws IOException {
        writeBase64(path, key.getEncoded());
    }

    public static void savePrivateKey(PrivateKey key, String path) throws IOException {
        writeBase64(path, key.getEncoded());
    }

    private static void writeBase64(String path, byte[] data) throws IOException {
        String encoded = Base64.getEncoder().encodeToString(data);
        Files.write(Paths.get(path), encoded.getBytes());
    }

    public static PublicKey loadPublicKey(String path) throws Exception {
        byte[] data = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(path)));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new X509EncodedKeySpec(data));
    }

    public static PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] data = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(path)));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(data));
    }

    /** Wrap (encrypt) a raw AES key with the recipient's RSA public key. */
    public static byte[] wrapKey(byte[] aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(aesKey);
    }

    /** Unwrap (decrypt) a wrapped AES key with the recipient's RSA private key. */
    public static byte[] unwrapKey(byte[] wrappedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(wrappedKey);
    }

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
}
