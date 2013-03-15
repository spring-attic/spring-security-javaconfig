package org.springframework.security.config.annotation.authentication;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.AbstractSecurityConfigurator;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class DaoAuthenticationConfigurator extends AbstractSecurityConfigurator<AuthenticationManager,AuthenticationRegistry> {
    private DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

    public DaoAuthenticationConfigurator(UserDetailsService userDetailsService) {
        provider.setUserDetailsService(userDetailsService);
    }

    public DaoAuthenticationConfigurator passwordEncoder(PasswordEncoder passwordEncoder) {
        provider.setPasswordEncoder(passwordEncoder);
        return this;
    }

    protected void doConfigure(AuthenticationRegistry builder) throws Exception {
        builder.add(provider);
    }
}
