package org.springframework.security.config.annotation.authentication;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class DaoAuthenticationProviderSecurityBuilder implements SecurityBuilder<DaoAuthenticationProvider> {
    private DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

    public DaoAuthenticationProviderSecurityBuilder(UserDetailsService userDetailsService) {
        provider.setUserDetailsService(userDetailsService);
    }

    @Override
    public DaoAuthenticationProvider build() throws Exception {
        return provider;
    }

    public DaoAuthenticationProviderSecurityBuilder passwordEncoder(PasswordEncoder passwordEncoder) {
        provider.setPasswordEncoder(passwordEncoder);
        return this;
    }
}
