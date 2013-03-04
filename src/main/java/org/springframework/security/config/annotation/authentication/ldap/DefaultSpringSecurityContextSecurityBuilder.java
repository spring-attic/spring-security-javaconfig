package org.springframework.security.config.annotation.authentication.ldap;

import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;

public class DefaultSpringSecurityContextSecurityBuilder implements
        SecurityBuilder<DefaultSpringSecurityContextSource> {
    private String userDn = "uid=admin,ou=system";
    private String password = "secret";

    @Override
    public DefaultSpringSecurityContextSource build() throws Exception {
        DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
                "ldap://127.0.0.1:33389/dc=springframework,dc=org");
        contextSource.afterPropertiesSet();
        contextSource.setUserDn(userDn);
        contextSource.setPassword(password);
        return contextSource;
    }
}