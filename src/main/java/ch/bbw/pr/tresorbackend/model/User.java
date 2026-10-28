package ch.bbw.pr.tresorbackend.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * User
 * @author Peter Rutschmann
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user")
public class User {
   @Id
   @GeneratedValue(strategy = GenerationType.IDENTITY)
   private Long id;

   @Column(nullable = false, name="first_name")
   private String firstName;

   @Column(nullable = false, name="last_name")
   private String lastName;

   @Column(nullable = false, unique = true)
   private String email;

   //bcrypt hash (contains its own salt), pepper is not part of it
   @Column(nullable = false)
   private String password;

   //salt to derive the AES key for the secrets of this user (Base64)
   @JsonIgnore
   @Column(name="encryption_salt")
   private String encryptionSalt;
}