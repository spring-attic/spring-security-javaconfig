package org.springframework.security.config.annotation.web;

import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter

class EnableWebSecurityTests extends BaseSpringSpec {

    def "@Bean(BeanIds.AUTHENTICATION_MANAGER) includes HttpConfiguration's AuthenticationRegistry"() {
        when:
            loadConfig(SecurityConfig)
            AuthenticationManager authenticationManager = context.getBean(AuthenticationManager)
            AnonymousAuthenticationToken anonymousAuthToken = findFilter(AnonymousAuthenticationFilter).createAuthentication(new MockHttpServletRequest())
        then:
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user", "password"))
            authenticationManager.authenticate(anonymousAuthToken)

    }


    @EnableWebSecurity
    @Configuration
    static class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void registerAuthentication(AuthenticationRegistry registry)
                throws Exception {
            registry
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER");
        }

        @Override
        protected void authorizeUrls(ExpressionUrlAuthorizations interceptUrls) {
            interceptUrls
                .antMatchers("/*").hasRole("USER");
        }

        @Override
        protected void configure(HttpConfigurator http) throws Exception {
            http
                .formLogin();
        }
    }
}
