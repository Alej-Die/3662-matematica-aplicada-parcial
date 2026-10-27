package ar.edu.matap.otp.web;

import ar.edu.matap.otp.service.OtpService;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {
    private final OtpService service;

    public ApiController(OtpService service) {
        this.service = service;
    }

    @GetMapping("/state")
    public Map<String, Object> state() {
        return service.state();
    }

    @PostMapping("/secret/random")
    public Map<String, Object> randomSecret() {
        service.newRandomSecret();
        return service.state();
    }

    @PostMapping("/secret/rfc")
    public Map<String, Object> rfcSecret() {
        service.setSecret(OtpService.RFC_SECRET);
        return service.state();
    }

    @PostMapping("/secret")
    public Map<String, Object> setSecret(@RequestBody Map<String, String> body) {
        service.setSecret(body.get("secret"));
        return service.state();
    }

    @GetMapping("/totp")
    public Map<String, Object> totp() {
        return service.currentTotp();
    }

    @PostMapping("/hotp/next")
    public Map<String, Object> nextHotp() {
        return service.nextHotp();
    }

    @PostMapping("/hotp/reset")
    public Map<String, Object> resetHotp() {
        service.resetCounters();
        return service.state();
    }

    @PostMapping("/verify")
    public Map<String, Object> verify(@RequestBody Map<String, String> body) {
        return service.verify(body.get("mode"), body.get("code"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> unreadable(HttpMessageNotReadableException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "La solicitud no tiene un formato válido."));
    }
}
