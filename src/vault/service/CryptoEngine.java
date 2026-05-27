package vault.service;

import vault.domain.CryptoResult;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

public final class CryptoEngine {
    // AES-GCM Security Constants tested heavily during enterprise security audits
    private static final String CRYPTO_ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";

    private static final int AES_KEY_BIT_LENGTH = 256;
    private static final int GCM_IV_BYTE_LENGTH = 12;
    private static final int GCM_TAG_BIT_LENGTH = 128;
    private static final int PBKDF2_ITERATIONS = 600_000; // Work factor against GPU attacks

    // Thread-safe cryptographic strong pseudo-random number generator
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private CryptoEngine() {
        throw new AssertionError("CryptoEngine cannot be instantiated.");
    }

    public static SecretKey deriveKey(char[] masterPassword, byte[] salt) throws Exception {
        // Convert byte[] to char[] safely because KeySpec requires characters
//        char[] passwordChars = new char[masterPassword.length];
//        for (int i =0; i< masterPassword.length; i++) {
//           passwordChars[i] = (char) masterPassword[i];
//        }

        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
            KeySpec spec = new PBEKeySpec(masterPassword, salt, PBKDF2_ITERATIONS, AES_KEY_BIT_LENGTH);
            SecretKey key = secretKeyFactory.generateSecret(spec);
            return new SecretKeySpec(key.getEncoded(), "AES");
        } finally {
            // ZERO-TRUST INVARIANT: Clean the short-lived password character array immediately
            Arrays.fill(masterPassword, '\0');
        }
    }
    /**
     * Derives a cryptographically strong AES-256 key from a variable master password array.
     */
    public static CryptoResult encrypt(byte[] plaintext, SecretKey secretKey) {
        byte[] iv = new byte[GCM_IV_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(iv); // Generate unique cryptographic nonce initialization vector

        try {
            Cipher cipher = Cipher.getInstance(CRYPTO_ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] ciphertext = cipher.doFinal(plaintext);
            // Wrap metadata in our domain container record
            return new CryptoResult.Success(ciphertext);
        } catch (Exception e) {
            return new CryptoResult.Failure("Encryption processing failed internally", e);
        }
    }

    public static CryptoResult decrypt(byte[] combinedPayload, SecretKey derivedKey){
        if (combinedPayload == null || combinedPayload.length < 28) {
            return new CryptoResult.Failure("Corrupted Ciphertext: Payload length is too short.", null);
        }

        try {
            // 2. Isolate the 12-byte IV from the front of the array
            byte[] iv = new byte[12];
            System.arraycopy(combinedPayload, 0, iv, 0, iv.length);

            // 3. Isolate the ciphertext bytes (everything after the first 12 bytes)
            int ciphertextLength = combinedPayload.length - iv.length;
            byte[] ciphertext = new byte[ciphertextLength];
            System.arraycopy(combinedPayload, iv.length, ciphertext, 0, ciphertextLength);

            // 4. Initialize the AES/GCM/NoPadding Cipher in DECRYPT_MODE
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); // 128-bit authentication tag
            cipher.init(Cipher.DECRYPT_MODE, derivedKey, parameterSpec);

            // 5. Execute core decryption math
            byte[] decryptedPlaintext = cipher.doFinal(ciphertext);

            // Return successful data algebraic token
            return new CryptoResult.Success(decryptedPlaintext);

        } catch (Exception e) {
            // Capture decryption failures (e.g., tampered file data, wrong master key)
            return new CryptoResult.Failure("Decryption Failed: Verification tag mismatch or corrupt key.", e);
        }
    }

}
