package me.itzg.spsecvaultexample;

import java.util.Collection;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

@Getter @Setter
@EqualsAndHashCode(callSuper = false)
public class VaultSpringAuthToken extends AbstractAuthenticationToken {
  public enum Type {
    APPROLE,
    TOKEN
  }

  private Type type;
  private String roleId;
  private String secretId;
  private String token;

  public VaultSpringAuthToken(Type type) {
    super(null);
    this.type = type;
  }

  public VaultSpringAuthToken(String token,
      Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.type = Type.TOKEN;
    this.token = token;
  }

  @Override
  public Object getCredentials() {
    return token;
  }

  @Override
  public Object getPrincipal() {
    return type;
  }
}
