package me.itzg.spsecvaultexample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  private final VaultAuthProvider vaultAuthProvider;

  @Autowired
  public WebSecurityConfig(VaultAuthProvider vaultAuthProvider) {
    this.vaultAuthProvider = vaultAuthProvider;
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(vaultAuthProvider);
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests().anyRequest().fullyAuthenticated()
        .and()
        .httpBasic()
        .and()
        .addFilterBefore(new VaultAuthFilter(authenticationManager()), BasicAuthenticationFilter.class);
  }

}
