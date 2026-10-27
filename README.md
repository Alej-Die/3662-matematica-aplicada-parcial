# Simulador 2FA — TOTP / HOTP

Trabajo práctico de Matemática Aplicada (2.º parcial, tema 9).

## Requisitos
- Java 17 o superior
- Maven 3.8+

## Ejecutar
```
mvn spring-boot:run
```
Abrir http://localhost:8080

## Tests (vectores oficiales de RFC 4226 y RFC 6238)
```
mvn test
```

## Estructura
- `crypto/Hotp.java` — HOTP: HMAC-SHA1, truncamiento dinámico, módulo 10^d
- `crypto/Totp.java` — TOTP: T = floor(t / 30) y delega en HOTP
- `crypto/Base32.java` — codificación del secreto (RFC 4648)
- `service/OtpService.java` — estado en memoria y validación en rol servidor
- `web/ApiController.java` — API REST (`/api/...`)
- `resources/static/` — GUI (HTML + CSS + JS, sin dependencias)

## Demo sugerida
1. TOTP: ver el código y la barra de 30 s; copiarlo al validador (válido); esperar a que venza y reintentar (inválido).
2. Botón "Secreto de los RFC" + pestaña HOTP: el primer código debe ser `755224` (RFC 4226, Apéndice D).
3. HOTP: generar 3 códigos sin validar y validar el último: el servidor se resincroniza. Reusar un código: rechazado.
4. Errores: secreto con caracteres inválidos, código de menos de 6 dígitos.
