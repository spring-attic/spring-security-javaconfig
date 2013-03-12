package org.springframework.security.config.annotation.authentication;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class DaoAuthenticationProviderSecurityBuilder implements SecurityBuilder<AuthenticationManager> {
    private DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

    public DaoAuthenticationProviderSecurityBuilder(UserDetailsService userDetailsService) {
        provider.setUserDetailsService(userDetailsService);
    }

    public AuthenticationManager build() throws Exception {
        return new AuthenticationManagerSecurityBuilder()
            .authenticationProvider(provider)
            .build();
    }

    public AuthenticationProvider authenticationProvider() {
        return provider;
    }

    public DaoAuthenticationProviderSecurityBuilder passwordEncoder(PasswordEncoder passwordEncoder) {
        provider.setPasswordEncoder(passwordEncoder);
        return this;
    }
}
