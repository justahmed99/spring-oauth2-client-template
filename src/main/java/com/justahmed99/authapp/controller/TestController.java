package com.justahmed99.authapp.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
  @GetMapping("/admin")
  public String admin() {
    return "this is admin";
  }

  @GetMapping("/regular")
  public String regular() {
    return "this is regular";
  }

  @GetMapping("/public")
  public String publicEndPoint() {
    return "this is public";
  }
}
