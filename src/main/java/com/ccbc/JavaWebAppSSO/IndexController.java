package com.ccbc.JavaWebAppSSO;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/home")
    public String home(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        String email = principal.getFirstAttribute("email");
        model.addAttribute("email", email);
        model.addAttribute("attributes", principal.getAttributes());
        return "home";
    }

    @GetMapping("/error")
    public String error() {
        return "error";
    }
}
