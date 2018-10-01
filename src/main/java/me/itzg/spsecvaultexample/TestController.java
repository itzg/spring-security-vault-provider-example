package me.itzg.spsecvaultexample;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

  @GetMapping("/hello")
  public String selfInfo(Authentication authentication) {
    return String.format("Hello, you have the roles %s", authentication.getAuthorities());
  }
}
