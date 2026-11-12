package ch.bbw.pr.tresorbackend.service;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;

/**
 * PasswordEncryptService
 *   used to hash password and verify match
 *   Pepper: same secret value for all users, only in the code, not in the db.
 *   Salt: created by bcrypt for every hash and stored inside the hash.
 * @author Peter Rutschmann
 */
@Service
public class PasswordEncryptService {
   private static final int BCRYPT_LOG_ROUNDS = 12;
   private final String pepper = "MeinGeheimerPepper1234";

   public String hashPassword(String password) {
      return BCrypt.hashpw(applyPepper(password), BCrypt.gensalt(BCRYPT_LOG_ROUNDS));
   }

   public boolean doPasswordMatch(String password, String hashedPassword) {
      try {
         return BCrypt.checkpw(applyPepper(password), hashedPassword);
      } catch (IllegalArgumentException e) {
         //stored value is not a valid bcrypt hash
         return false;
      }
   }

   //the pepper is appended to the password
   private String applyPepper(String password) {
      return password + pepper;
   }
}