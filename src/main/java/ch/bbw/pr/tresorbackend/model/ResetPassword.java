package ch.bbw.pr.tresorbackend.model;

import ch.bbw.pr.tresorbackend.util.PasswordValidator;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.*;

/**
 * ResetPassword
 *   DTO for setting a new password with the token from the reset link
 * @author Peter Rutschmann
 */
@Value
public class ResetPassword {

  @NotEmpty (message="Token is required.")
  private String token;

  @NotEmpty (message="Password is required.")
  @Pattern(regexp = PasswordValidator.PASSWORD_REGEX, message = PasswordValidator.PASSWORD_MESSAGE)
  private String password;

  @NotEmpty (message="Password-confirmation is required.")
  private String passwordConfirmation;
}
