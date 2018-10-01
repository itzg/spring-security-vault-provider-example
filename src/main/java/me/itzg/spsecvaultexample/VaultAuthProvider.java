package me.itzg.spsecvaultexample;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.vault.VaultException;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;

@Component
@Slf4j
public class VaultAuthProvider implements AuthenticationProvider {

  private static final String CLIENT_TOKEN = "client_token";
  private static final String POLICIES = "policies";
  private final VaultWebAuthProperties vaultProperties;
  private final VaultTemplate vaultTemplate;
  @Getter @Setter
  private String userPassMount = "userpass";
  @Getter @Setter
  private String appRoleMount = "approle";

  @Autowired
  public VaultAuthProvider(VaultWebAuthProperties vaultProperties, VaultTemplate vaultTemplate) {
    this.vaultProperties = vaultProperties;
    this.vaultTemplate = vaultTemplate;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (authentication.isAuthenticated()) {
      return authentication;
    }

    log.debug("Authenticating type={}", authentication.getClass());

    if (authentication instanceof VaultSpringAuthToken) {
      final VaultSpringAuthToken vaultSpringAuthToken = (VaultSpringAuthToken) authentication;
      switch (vaultSpringAuthToken.getType()) {
        case TOKEN:
          return handleToken(vaultSpringAuthToken);
        case APPROLE:
          return handleAppRole(vaultSpringAuthToken);
      }
    } else if (authentication instanceof UsernamePasswordAuthenticationToken) {
      return handleUsernamePassword(((UsernamePasswordAuthenticationToken) authentication));
    }

    return null;
  }

  private Authentication handleAppRolePull(VaultSpringAuthToken vaultSpringAuthToken) {
    return null;
  }

  private Authentication handleToken(VaultSpringAuthToken vaultSpringAuthToken) {
    final HttpHeaders headers = new HttpHeaders();
    headers.add("X-Vault-Token", vaultSpringAuthToken.getToken());
    final HttpEntity<String> entity = new HttpEntity<>("", headers);
    try {
      return vaultTemplate.doWithVault(restOperations -> {
        final ResponseEntity<VaultResponse> response = restOperations
            .exchange("/auth/token/lookup-self", HttpMethod.GET, entity, VaultResponse.class);

        return createAuthResult(
            vaultSpringAuthToken.getToken(),
            (List<String>) response.getBody().getData().get(POLICIES)
        );
      });
    } catch (VaultException e) {
      throw new BadCredentialsException("Failed to login with token", e);
    }
  }

  private Authentication handleUsernamePassword(
      UsernamePasswordAuthenticationToken authentication) {
    Map<String, String> body = new HashMap<>();
    body.put("password", authentication.getCredentials().toString());

    try {
      return vaultTemplate.doWithVault(restOperations -> {
        VaultResponse response = (VaultResponse) restOperations
            .postForObject("auth/{mount}/login/{username}",
                body, VaultResponse.class, new Object[]{userPassMount, authentication.getName()}
            );

        final Map<String, Object> auth = response.getAuth();

        final String token = (String) auth.get(CLIENT_TOKEN);
        final List<String> policies = (List<String>) auth.get(POLICIES);

        return createAuthResult(token, policies);
      });
    } catch (VaultException e) {
      throw new BadCredentialsException("Failed to authenticate with userpass", e);
    }
  }

  private Authentication handleAppRole(VaultSpringAuthToken authentication) {
    Map<String, String> body = new HashMap<>();
    body.put("role_id", authentication.getRoleId());
    body.put("secret_id", authentication.getSecretId());

    try {
      return vaultTemplate.doWithVault(restOperations -> {
        VaultResponse response = (VaultResponse) restOperations
            .postForObject("auth/{mount}/login",
                body, VaultResponse.class, new Object[]{appRoleMount}
            );

        final Map<String, Object> auth = response.getAuth();

        final String token = (String) auth.get(CLIENT_TOKEN);
        final List<String> policies = (List<String>) auth.get(POLICIES);

        return createAuthResult(token, policies);
      });
    } catch (VaultException e) {
      throw new BadCredentialsException("Failed to authenticate with approle", e);
    }
  }

  private Authentication createAuthResult(String token, List<String> policies) {
    final List<SimpleGrantedAuthority> grantedAuthorities = policies.stream()
        .map(s -> vaultProperties.getRoleMappings().get(s))
        .filter(Objects::nonNull)
        .map(s -> new SimpleGrantedAuthority("ROLE_" + s))
        .collect(Collectors.toList());

    final VaultSpringAuthToken authResult = new VaultSpringAuthToken(
        token,
        grantedAuthorities
    );
    authResult.setAuthenticated(true);

    return authResult;
  }

  @Override
  public boolean supports(Class<?> auth) {
    return auth.equals(UsernamePasswordAuthenticationToken.class) ||
        auth.equals(VaultSpringAuthToken.class);
  }
}
