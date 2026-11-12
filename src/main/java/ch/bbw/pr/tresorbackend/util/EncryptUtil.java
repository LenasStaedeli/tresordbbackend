package ch.bbw.pr.tresorbackend.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * EncryptUtil
 * Used to encrypt and decrypt the content of a secret.
 * The AES key is built from the password of the user and the salt of the user.
 * @author Peter Rutschmann
 */
public class EncryptUtil {

   private SecretKey secretKey;

   //creates a new random salt, it is saved in the db for each user
   public static String generateSalt() {
      byte[] salt = new byte[16];
      new SecureRandom().nextBytes(salt);
      return Base64.getEncoder().encodeToString(salt);
   }

   //builds the AES key from password and salt
   public EncryptUtil(String password, String salt) {
      try {
         SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
         PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 65536, 256);
         secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
      } catch (Exception e) {
         throw new RuntimeException("Key could not be created", e);
      }
   }

   public String encrypt(String data) {
      try {
         byte[] iv = new byte[16];
         new SecureRandom().nextBytes(iv);

         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
         cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
         byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

         byte[] result = new byte[iv.length + encrypted.length];
         System.arraycopy(iv, 0, result, 0, iv.length);
         System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);

         return Base64.getEncoder().encodeToString(result);
      } catch (Exception e) {
         throw new RuntimeException("Encryption failed", e);
      }
   }

   public String decrypt(String data) {
      try {
         byte[] all = Base64.getDecoder().decode(data);
         byte[] iv = Arrays.copyOfRange(all, 0, 16);
         byte[] encrypted = Arrays.copyOfRange(all, 16, all.length);

         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
         cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
         return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
      } catch (Exception e) {
         throw new RuntimeException("Decryption failed", e);
      }
   }
}