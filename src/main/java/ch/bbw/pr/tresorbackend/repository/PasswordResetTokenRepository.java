package ch.bbw.pr.tresorbackend.repository;

import ch.bbw.pr.tresorbackend.model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

/**
 * PasswordResetTokenRepository
 * @author Peter Rutschmann
 */
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
  Optional<PasswordResetToken> findByToken(String token);

  List<PasswordResetToken> findByUserId(Long userId);
}