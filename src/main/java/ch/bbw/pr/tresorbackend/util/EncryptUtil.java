package ch.bbw.pr.tresorbackend.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * EncryptUtil
 * Used to encrypt and decrypt the content of secrets.
 *   Key: PBKDF2(password, salt of the user) -> AES-256 key, never stored.
 *   Cipher: AES-256-GCM with a random IV. Stored as Base64( IV + ciphertext ).
 * @author Peter Rutschmann
 */
public class EncryptUtil {
   private static final int PBKDF2_ITERATIONS = 310_000; //lower this if too slow on your machine
   private static final int KEY_LENGTH_BITS = 256;
   private static final int SALT_LENGTH_BYTES = 16;
   private static final int IV_LENGTH_BYTES = 12;
   private static final int GCM_TAG_BITS = 128;
   private static final SecureRandom RANDOM = new SecureRandom();

   private final SecretKeySpec secretKey;

   //thrown if decryption is not possible: wrong password, wrong salt, or content is not encrypted
   public static class DecryptionException extends RuntimeException {
      public DecryptionException(String message, Throwable cause) {
         super(message, cause);
      }
   }

   //new random salt for a user (Base64), to be stored in the db
   public static String generateSalt() {
      byte[] salt = new byte[SALT_LENGTH_BYTES];
      RANDOM.nextBytes(salt);
      return Base64.getEncoder().encodeToString(salt);
   }

   public EncryptUtil(String password, String saltBase64) {
      if (saltBase64 == null) {
         throw new IllegalStateException("User has no encryption salt.");
      }
      PBEKeySpec spec = null;
      try {
         byte[] salt = Base64.getDecoder().decode(saltBase64);
         spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
         byte[] keyBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                 .generateSecret(spec).getEncoded();
         this.secretKey = new SecretKeySpec(keyBytes, "AES");
      } catch (Exception e) {
         throw new IllegalStateException("Key derivation failed", e);
      } finally {
         if (spec != null) spec.clearPassword();
      }
   }

   public String encrypt(String data) {
      try {
         byte[] iv = new byte[IV_LENGTH_BYTES];
         RANDOM.nextBytes(iv); //new IV for every encryption
         Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
         cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
         byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
         byte[] ivAndCipher = ByteBuffer.allocate(iv.length + encrypted.length)
                 .put(iv).put(encrypted).array();
         return Base64.getEncoder().encodeToString(ivAndCipher);
      } catch (Exception e) {
         throw new IllegalStateException("Encryption failed", e);
      }
   }

   public String decrypt(String data) {
      try {
         byte[] ivAndCipher = Base64.getDecoder().decode(data);
         byte[] iv = new byte[IV_LENGTH_BYTES];
         System.arraycopy(ivAndCipher, 0, iv, 0, IV_LENGTH_BYTES);
         Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
         cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
         byte[] decrypted = cipher.doFinal(ivAndCipher, IV_LENGTH_BYTES, ivAndCipher.length - IV_LENGTH_BYTES);
         return new String(decrypted, StandardCharsets.UTF_8);
      } catch (Exception e) {
         throw new DecryptionException("Decryption failed", e);
      }
   }
}