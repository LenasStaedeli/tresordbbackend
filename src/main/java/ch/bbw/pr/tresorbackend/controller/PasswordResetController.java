package ch.bbw.pr.tresorbackend.controller;

import ch.bbw.pr.tresorbackend.model.EmailAdress;
import ch.bbw.pr.tresorbackend.model.PasswordResetToken;
import ch.bbw.pr.tresorbackend.model.ResetPassword;
import ch.bbw.pr.tresorbackend.model.Secret;
import ch.bbw.pr.tresorbackend.model.User;
import ch.bbw.pr.tresorbackend.repository.PasswordResetTokenRepository;
import ch.bbw.pr.tresorbackend.service.PasswordEncryptService;
import ch.bbw.pr.tresorbackend.service.SecretService;
import ch.bbw.pr.tresorbackend.service.UserService;
import ch.bbw.pr.tresorbackend.util.EncryptUtil;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * PasswordResetController
 *   Forgot password: 1. request a reset link, 2. set a new password with the token of the link.
 * @author Peter Rutschmann
 */
@RestController
@AllArgsConstructor
@RequestMapping("api/password")
public class PasswordResetController {

  private static final int EXPIRATION_HOURS = 1;
  private static final String RESET_LINK = "http://localhost:3000/user/reset?token=";

  private UserService userService;
  private SecretService secretService;
  private PasswordEncryptService passwordService;
  private PasswordResetTokenRepository tokenRepository;

  // step 1: user has forgotten the password and sends his e-mail
  @CrossOrigin(origins = "${CROSS_ORIGIN}")
  @PostMapping("/forgot")
  public ResponseEntity<String> forgotPassword(@Valid @RequestBody EmailAdress emailAdress, BindingResult bindingResult) {
    if (bindingResult.hasErrors()) {
      return badRequest("E-Mail is required.");
    }

    User user = userService.findByEmail(emailAdress.getEmail());
    if (user != null) {
      //only one valid token per user
      tokenRepository.deleteAll(tokenRepository.findByUserId(user.getId()));

      String token = UUID.randomUUID().toString();
      PasswordResetToken resetToken = new PasswordResetToken(
              null, token, user.getId(), LocalDateTime.now().plusHours(EXPIRATION_HOURS));
      tokenRepository.save(resetToken);

      //no e-mail is sent in this project, the link is written to the console
      System.out.println("PasswordResetController.forgotPassword: reset link for "
              + user.getEmail() + " (valid " + EXPIRATION_HOURS + " hour): " + RESET_LINK + token);
    } else {
      System.out.println("PasswordResetController.forgotPassword: e-mail is not registered");
    }

    //same answer in both cases, so nobody can find out which e-mails are registered
    JsonObject obj = new JsonObject();
    obj.addProperty("answer", "If the e-mail is registered, a reset link was created.");
    return ResponseEntity.ok(new Gson().toJson(obj));
  }

  // step 2: user opens the link and sends the new password with the token
  @CrossOrigin(origins = "${CROSS_ORIGIN}")
  @PostMapping("/reset")
  public ResponseEntity<String> resetPassword(@Valid @RequestBody ResetPassword resetPassword, BindingResult bindingResult) {
    //input validation, includes the password strength rule
    if (bindingResult.hasErrors()) {
      String message = bindingResult.getFieldErrors().stream()
              .map(fieldError -> fieldError.getDefaultMessage())
              .collect(Collectors.joining(" "));
      return badRequest(message);
    }

    if (!resetPassword.getPassword().equals(resetPassword.getPasswordConfirmation())) {
      return badRequest("Password and password-confirmation are not equal.");
    }

    //token has to exist and must not be expired
    PasswordResetToken resetToken = tokenRepository.findByToken(resetPassword.getToken()).orElse(null);
    if (resetToken == null) {
      return badRequest("The reset link is not valid.");
    }
    if (resetToken.getExpiryDate().isBefore(LocalDateTime.now())) {
      tokenRepository.delete(resetToken);
      return badRequest("The reset link is expired. Please request a new one.");
    }

    User user = userService.getUserById(resetToken.getUserId());
    if (user == null) {
      return badRequest("The reset link is not valid.");
    }

    //new password hash and a new salt for the key of the new secrets
    user.setPassword(passwordService.hashPassword(resetPassword.getPassword()));
    user.setEncryptionSalt(EncryptUtil.generateSalt());
    //save() updates the existing user, because the id is set
    if (userService.createUser(user) == null) {
      return badRequest("The password could not be saved.");
    }

    //the old secrets are encrypted with the old password and can not be decrypted anymore
    List<Secret> oldSecrets = secretService.getSecretsByUserId(user.getId());
    if (oldSecrets != null) {
      for (Secret secret : oldSecrets) {
        secretService.deleteSecret(secret.getId());
      }
    }

    //a token can be used only once
    tokenRepository.delete(resetToken);

    System.out.println("PasswordResetController.resetPassword: password reset for user " + user.getId());
    JsonObject obj = new JsonObject();
    obj.addProperty("answer", "Password was reset.");
    return ResponseEntity.ok(new Gson().toJson(obj));
  }

  //error answer in the same format as in the UserController: {"message": ["..."]}
  private ResponseEntity<String> badRequest(String message) {
    JsonArray arr = new JsonArray();
    arr.add(message);
    JsonObject obj = new JsonObject();
    obj.add("message", arr);
    return ResponseEntity.badRequest().body(new Gson().toJson(obj));
  }
}