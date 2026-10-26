package ch.bbw.pr.tresorbackend.service;

import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import org.mindrot.jbcrypt.BCrypt;

/**
 * PasswordEncryptService
 *   used to hash password and verify match
 * @author Peter Rutschmann
 */
@Service
public class PasswordEncryptService {
   private static String pepper = "[\\pK$F-J_!g2l\\c`*@2IT1X`vVWR|9b*.\\t}BwALrf.!J![fU]K[B\\>I'L>GY!ql5$j*wk-]<OnVyJ7/p,kZi'|X7DW3;sQfoT](Bq)9Ta~vc_*oJ:iR^)`|.q:=7uf1Z#a~A7HK^^mz'N7j-R[rYW^n:sv_FXj:I!y_.JtAo'3L2fJS1`d1HrbGNpie{5+!QLd`1i].";
   //todo add implementation here

   public PasswordEncryptService() {
      //todo add implementation here
   }

   public static String hashPassword(String password) {
      // Define a cost factor (work factor). Default is 10.
      int logRounds = 12;  // Increasing this value makes it more secure, but slower

      // Generate the salt
      String salt = BCrypt.gensalt(logRounds);

      // Hash the password with the salt
      return BCrypt.hashpw(password + pepper, salt);
   }

   public boolean doPasswordMatch(String password, String hashedPassword){
      return BCrypt.checkpw(password, hashedPassword);
   }

   //Todo add password match function: password vs hashedPassword

}