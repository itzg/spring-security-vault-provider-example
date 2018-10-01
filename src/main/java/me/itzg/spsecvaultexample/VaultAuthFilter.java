package me.itzg.spsecvaultexample;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import me.itzg.spsecvaultexample.VaultSpringAuthToken.Type;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
public class VaultAuthFilter extends OncePerRequestFilter {

  private final AuthenticationManager authenticationManager;
  private Charset credentialsCharSet = StandardCharsets.UTF_8;

  @Autowired
  public VaultAuthFilter(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request,
      HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {

    String header = request.getHeader("Authorization");

    if (header != null) {
      final String[] headerParts = header.split(" ", 2);

      if (headerParts.length == 2) {
        final String authType = headerParts[0];
        log.debug("Checking for handling of authorization type={}", authType);

        final VaultSpringAuthToken springAuthToken;
        switch (authType.toLowerCase()) {
          case "approle": {
            final String[] parts = headerParts[1].split(":", 2);
            if (parts.length != 2) {
              throw new BadCredentialsException("Malformed credentials content");
            }
            springAuthToken = new VaultSpringAuthToken(Type.APPROLE)
                .setRoleId(parts[0])
                .setSecretId(parts[1]);
            break;
          }

          case "token": {
            springAuthToken = new VaultSpringAuthToken(Type.TOKEN)
                .setToken(headerParts[1]);
            break;
          }

          default:
            log.debug("Skipping unknown authorization type: {}", authType);
            chain.doFilter(request, response);
            return;
        }

        final Authentication authResult = authenticationManager.authenticate(springAuthToken);
        SecurityContextHolder.getContext().setAuthentication(authResult);
      }
    }

    chain.doFilter(request, response);
  }
}
