package com.ccbc.JavaWebAppSSO;

import org.opensaml.saml.common.assertion.ValidationContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters.CLOCK_SKEW;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired(required = true)
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //entry level validation, only asserts that time difference between IDP and SP is < 10 mins
        OpenSamlAuthenticationProvider authenticationProvider = new OpenSamlAuthenticationProvider();
        authenticationProvider.setAssertionValidator(OpenSamlAuthenticationProvider
                .createDefaultAssertionValidator(assertionToken -> {
                    Map<String, Object> params = new HashMap<>();
                    params.put(CLOCK_SKEW, Duration.ofMinutes(10).toMillis());
                    // ... other validation parameters
                    return new ValidationContext(params);
                })
        );

        Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver =
                new DefaultRelyingPartyRegistrationResolver(this.relyingPartyRegistrationRepository);

        Saml2MetadataFilter filter = new Saml2MetadataFilter(
                relyingPartyRegistrationResolver,
                new OpenSamlMetadataResolver());

        //filter.setRequestMatcher(new AntPathRequestMatcher("/saml2/{registrationId}", "GET"));
        //System.out.println(getRelyingPartyRegistrationRepository());

        http
                .saml2Login(saml2 -> saml2
                        .authenticationManager(new ProviderManager(authenticationProvider))
                )
                .addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class)
                .mvcMatcher("/**")
                .authorizeRequests()
                .mvcMatchers("/**").authenticated();
    }

    public RelyingPartyRegistrationRepository getRelyingPartyRegistrationRepository() {
        return relyingPartyRegistrationRepository;
    }
}
