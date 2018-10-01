package me.itzg.spsecvaultexample;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.vault.config.EnvironmentVaultConfiguration;

@Configuration
@Import(EnvironmentVaultConfiguration.class)
public class VaultWebAuthConfiguration {

}
