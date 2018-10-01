package me.itzg.spsecvaultexample;

import java.util.Map;
import javax.validation.constraints.NotEmpty;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@ConfigurationProperties("vault-web-auth")
@Validated
@Data
public class VaultWebAuthProperties {

  /**
   * Maps Vault policy names to Spring Security role (without the leading ROLE_ prefix)
   */
  @NotEmpty
  Map<String,String> roleMappings;
}
