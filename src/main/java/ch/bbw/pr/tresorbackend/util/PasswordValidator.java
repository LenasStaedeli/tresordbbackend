package ch.bbw.pr.tresorbackend.util;

public class PasswordValidator {

  public static final String PASSWORD_REGEX =
          "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&+=!?*._-])(?=\\S+$).{8,30}$";

  public static final String PASSWORD_MESSAGE =
          "Password requirements: 8 to 30 characters, one uppercase letter, one lowercase letter, "
                  + "one digit, one special character (@#$%^&+=!?*._-) and no whitespace.";

  public static boolean isPasswordStrong(String password) {
    return password != null && password.matches(PASSWORD_REGEX);
  }
}