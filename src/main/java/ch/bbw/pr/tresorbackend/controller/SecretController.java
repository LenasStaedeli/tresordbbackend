package ch.bbw.pr.tresorbackend.controller;

import ch.bbw.pr.tresorbackend.model.Secret;
import ch.bbw.pr.tresorbackend.model.NewSecret;
import ch.bbw.pr.tresorbackend.model.EncryptCredentials;
import ch.bbw.pr.tresorbackend.model.User;
import ch.bbw.pr.tresorbackend.service.SecretService;
import ch.bbw.pr.tresorbackend.service.UserService;
import ch.bbw.pr.tresorbackend.util.EncryptUtil;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * SecretController
 * @author Peter Rutschmann
 */
@RestController
@AllArgsConstructor
@RequestMapping("api/secrets")
public class SecretController {

   private SecretService secretService;
   private UserService userService;

   // create secret REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping
   public ResponseEntity<String> createSecret2(@Valid @RequestBody NewSecret newSecret, BindingResult bindingResult) {
      //input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
                 .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
                 .collect(Collectors.toList());
         System.out.println("SecretController.createSecret " + errors);

         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);

         System.out.println("SecretController.createSecret, validation fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }
      System.out.println("SecretController.createSecret, input validation passed");

      User user = userService.findByEmail(newSecret.getEmail());
      if (user == null) return ResponseEntity.notFound().build();

      //key = PBKDF2(password, salt of this user), then encrypt content
      EncryptUtil crypto = new EncryptUtil(newSecret.getEncryptPassword(), user.getEncryptionSalt());
      Secret secret = new Secret(
              null,
              user.getId(),
              crypto.encrypt(newSecret.getContent().toString())
      );
      //save secret in db
      secretService.createSecret(secret);
      System.out.println("SecretController.createSecret, secret saved in db");
      JsonObject obj = new JsonObject();
      obj.addProperty("answer", "Secret saved");
      String json = new Gson().toJson(obj);
      System.out.println("SecretController.createSecret " + json);
      return ResponseEntity.accepted().body(json);
   }

   // Build Get Secrets by userId REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping("/byuserid")
   public ResponseEntity<List<Secret>> getSecretsByUserId(@RequestBody EncryptCredentials credentials) {
      //never print credentials: they contain the password
      System.out.println("SecretController.getSecretsByUserId for user " + credentials.getUserId());

      User user = userService.getUserById(credentials.getUserId());
      if (user == null) return ResponseEntity.notFound().build();

      return decryptSecretsOfUser(user, credentials.getEncryptPassword());
   }

   // Build Get Secrets by email REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping("/byemail")
   public ResponseEntity<List<Secret>> getSecretsByEmail(@RequestBody EncryptCredentials credentials) {
      System.out.println("SecretController.getSecretsByEmail for " + credentials.getEmail());

      User user = userService.findByEmail(credentials.getEmail());
      if (user == null) return ResponseEntity.notFound().build();

      return decryptSecretsOfUser(user, credentials.getEncryptPassword());
   }

   //load all secrets of a user and decrypt the content.
   //The result are copies, the entities from the db are not modified (decrypted content must never be saved).
   private ResponseEntity<List<Secret>> decryptSecretsOfUser(User user, String encryptPassword) {
      List<Secret> secrets = secretService.getSecretsByUserId(user.getId());
      if (secrets == null || secrets.isEmpty()) {
         System.out.println("SecretController.decryptSecretsOfUser: no secrets for user " + user.getId());
         return ResponseEntity.notFound().build();
      }

      //key is derived only once per request
      EncryptUtil crypto = new EncryptUtil(encryptPassword, user.getEncryptionSalt());

      List<Secret> decryptedSecrets = new ArrayList<>();
      for (Secret secret : secrets) {
         String content;
         try {
            content = crypto.decrypt(secret.getContent());
         } catch (EncryptUtil.DecryptionException e) {
            System.out.println("SecretController.decryptSecretsOfUser: secret " + secret.getId() + " not decryptable");
            content = "not decryptable. Wrong password?";
         }
         decryptedSecrets.add(new Secret(secret.getId(), secret.getUserId(), content));
      }
      return ResponseEntity.ok(decryptedSecrets);
   }

   // Build Get All Secrets REST API
   // http://localhost:8080/api/secrets
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @GetMapping
   public ResponseEntity<List<Secret>> getAllSecrets() {
      List<Secret> secrets = secretService.getAllSecrets();
      return new ResponseEntity<>(secrets, HttpStatus.OK);
   }

   // Build Update Secrete REST API
   // http://localhost:8080/api/secrets/1
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PutMapping("{id}")
   public ResponseEntity<String> updateSecret(
           @PathVariable("id") Long secretId,
           @Valid @RequestBody NewSecret newSecret,
           BindingResult bindingResult) {
      //input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
                 .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
                 .collect(Collectors.toList());
         System.out.println("SecretController.createSecret " + errors);

         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);

         System.out.println("SecretController.updateSecret, validation fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }

      //get Secret with id
      Secret dbSecrete = secretService.getSecretById(secretId);
      if(dbSecrete == null){
         System.out.println("SecretController.updateSecret, secret not found in db");
         JsonObject obj = new JsonObject();
         obj.addProperty("answer", "Secret not found in db");
         String json = new Gson().toJson(obj);
         System.out.println("SecretController.updateSecret failed:" + json);
         return ResponseEntity.badRequest().body(json);
      }
      User user = userService.findByEmail(newSecret.getEmail());
      if (user == null) return ResponseEntity.notFound().build();

      //check if Secret in db has not same userid (equals, because these are Long objects)
      if(!dbSecrete.getUserId().equals(user.getId())){
         System.out.println("SecretController.updateSecret, not same user id");
         JsonObject obj = new JsonObject();
         obj.addProperty("answer", "Secret has not same user id");
         String json = new Gson().toJson(obj);
         System.out.println("SecretController.updateSecret failed:" + json);
         return ResponseEntity.badRequest().body(json);
      }
      EncryptUtil crypto = new EncryptUtil(newSecret.getEncryptPassword(), user.getEncryptionSalt());
      //check if Secret can be decrypted with password
      try {
         crypto.decrypt(dbSecrete.getContent());
      } catch (EncryptUtil.DecryptionException e) {
         System.out.println("SecretController.updateSecret, invalid password");
         JsonObject obj = new JsonObject();
         obj.addProperty("answer", "Password not correct.");
         String json = new Gson().toJson(obj);
         System.out.println("SecretController.updateSecret failed:" + json);
         return ResponseEntity.badRequest().body(json);
      }
      //modify Secret in db.
      Secret secret = new Secret(
              secretId,
              user.getId(),
              crypto.encrypt(newSecret.getContent().toString())
      );
      Secret updatedSecret = secretService.updateSecret(secret);
      //save secret in db
      secretService.createSecret(secret);
      System.out.println("SecretController.updateSecret, secret updated in db");
      JsonObject obj = new JsonObject();
      obj.addProperty("answer", "Secret updated");
      String json = new Gson().toJson(obj);
      System.out.println("SecretController.updateSecret " + json);
      return ResponseEntity.accepted().body(json);
   }

   // Build Delete Secret REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @DeleteMapping("{id}")
   public ResponseEntity<String> deleteSecret(@PathVariable("id") Long secretId) {
      //todo: Some kind of brute force delete, perhaps test first userid and encryptpassword
      secretService.deleteSecret(secretId);
      System.out.println("SecretController.deleteSecret succesfully: " + secretId);
      return new ResponseEntity<>("Secret successfully deleted!", HttpStatus.OK);
   }
}