package org.springframework.security.config.annotation.authentication;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.SecurityConfiguratorAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class DaoAuthenticationConfigurator<T extends UserDetailsService> extends SecurityConfiguratorAdapter<AuthenticationManager,AuthenticationManagerBuilder> {
    private DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    private final T userDetailsService;

    public DaoAuthenticationConfigurator(T userDetailsService) {
        this.userDetailsService = userDetailsService;
        provider.setUserDetailsService(userDetailsService);
    }

    public DaoAuthenticationConfigurator passwordEncoder(PasswordEncoder passwordEncoder) {
        provider.setPasswordEncoder(passwordEncoder);
        return this;
    }

    @Override
    public void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder.add(provider);
    }

    protected T getUserDetailsService() throws Exception {
        return userDetailsService;
    }
}
