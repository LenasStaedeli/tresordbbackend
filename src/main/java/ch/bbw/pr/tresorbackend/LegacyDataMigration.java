package ch.bbw.pr.tresorbackend;

import ch.bbw.pr.tresorbackend.model.Secret;
import ch.bbw.pr.tresorbackend.model.User;
import ch.bbw.pr.tresorbackend.repository.SecretRepository;
import ch.bbw.pr.tresorbackend.repository.UserRepository;
import ch.bbw.pr.tresorbackend.service.PasswordEncryptService;
import ch.bbw.pr.tresorbackend.util.EncryptUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/**
 * LegacyDataMigration
 *   Replaces plaintext passwords (from the old sql-script) by hashes and
 *   encrypts the plaintext secrets of these users. Runs on every start, but changes
 *   only users whose password is not yet a bcrypt hash.
 */
@Component
public class LegacyDataMigration implements CommandLineRunner {
  private static final Logger log = LoggerFactory.getLogger(LegacyDataMigration.class);

  private final UserRepository userRepository;
  private final SecretRepository secretRepository;
  private final PasswordEncryptService passwordService;

  public LegacyDataMigration(UserRepository userRepository,
                             SecretRepository secretRepository,
                             PasswordEncryptService passwordService) {
    this.userRepository = userRepository;
    this.secretRepository = secretRepository;
    this.passwordService = passwordService;
  }

  @Override
  public void run(String... args) {
    try {
      for (User user : userRepository.findAll()) {
        if (isBcryptHash(user.getPassword())) continue;

        String plainPassword = user.getPassword();
        String salt = EncryptUtil.generateSalt();
        EncryptUtil crypto = new EncryptUtil(plainPassword, salt);

        //secrets first: if this fails (e.g. content column still json), the user stays unchanged
        for (Secret secret : secretRepository.findByUserId(user.getId())) {
          secret.setContent(crypto.encrypt(secret.getContent()));
          secretRepository.save(secret);
        }
        user.setPassword(passwordService.hashPassword(plainPassword));
        user.setEncryptionSalt(salt);
        userRepository.save(user);
        log.info("LegacyDataMigration: user {} migrated (password hashed, secrets encrypted)", user.getId());
      }
    } catch (Exception e) {
      //db not available or schema not yet changed: do not stop the application
      log.warn("LegacyDataMigration skipped: {}", e.toString());
    }
  }

  private boolean isBcryptHash(String value) {
    return value != null && value.matches("^\\$2[aby]\\$\\d{2}\\$.{53}$");
  }
}