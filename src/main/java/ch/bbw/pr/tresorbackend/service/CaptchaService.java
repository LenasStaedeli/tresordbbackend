package ch.bbw.pr.tresorbackend.service;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
@Service
public class CaptchaService {
  private static final String VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

  @Value("${recaptcha.secret}")
  private String secret;

  public boolean verifyCaptcha(String token) {
    if (token == null || token.isEmpty()) {
      return false;
    }
    try {
      String body = "secret=" + URLEncoder.encode(secret, StandardCharsets.UTF_8)
              + "&response=" + URLEncoder.encode(token, StandardCharsets.UTF_8);

      HttpRequest request = HttpRequest.newBuilder()
              .uri(URI.create(VERIFY_URL))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .timeout(Duration.ofSeconds(10))
              .POST(HttpRequest.BodyPublishers.ofString(body))
              .build();

      HttpResponse<String> response = HttpClient.newHttpClient()
              .send(request, HttpResponse.BodyHandlers.ofString());

      //google answers with json: {"success": true, ...}
      JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
      return json.has("success") && json.get("success").getAsBoolean();
    } catch (Exception e) {
      System.out.println("CaptchaService.verifyCaptcha failed: " + e);
      return false;
    }
  }
}