/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.AuthenticationRegistry;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

/**
 * Provides a convenient base class for creating a {@link WebSecurityConfigurer}
 * instance. The implementation allows customization by overriding methods.
 *
 * @see EnableWebSecurity
 *
 * @author Rob Winch
 */
public abstract class WebSecurityConfigurerAdapter implements WebSecurityConfigurer {
    @Autowired
    private ApplicationContext context;

    private final AuthenticationManagerBuilder authenticationBuilder = new AuthenticationManagerBuilder();
    private AuthenticationManagerBuilder parentAuthenticationRegistry = new AuthenticationManagerBuilder();
    private boolean disableAuthenticationRegistry;
    private boolean authenticationManagerInitialized;
    private AuthenticationManager authenticationManager;
    private HttpConfiguration http;
    private boolean disableDefaults;

    /**
     * Creates an instance with the default configuration enabled.
     */
    protected WebSecurityConfigurerAdapter() {
        this(false);
    }

    /**
     * Creates an instance which allows specifying if the default configuration
     * should be enabled. Disabling the default configuration should be
     * considered more advanced usage as it requires more understanding of how
     * the framework is implemented.
     *
     * @param disableDefaults
     *            true if the default configuration should be enabled, else
     *            false
     */
    protected WebSecurityConfigurerAdapter(boolean disableDefaults) {
        this.disableDefaults = disableDefaults;
    }

    /**
     * Used by the default implementation of {@link #authenticationManager()} to attempt to obtain an
     * {@link AuthenticationManager}. If overridden, the {@link AuthenticationRegistry} should be used to specify
     * the {@link AuthenticationManager}. The resulting {@link AuthenticationManager}
     * will be exposed as a Bean as will any {@link UserDetailsService} that is created with the
     * {@link AuthenticationRegistry}. For example, the following configuration could be used to register
     * in memory authentication that exposes an in memory {@link UserDetailsService}:
     *
     * <pre>
     * &#064;Override
     * protected void registerAuthentication(AuthenticationRegistry registry) {
     *     registry
     *         // enable in memory based authentication with a user named "user" and "admin"
     *         .inMemoryAuthentication()
     *             .withUser("user").password("password").roles("USER").and()
     *             .withUser("admin").password("password").roles("USER", "ADMIN");
     * }
     * </pre>
     *
     * @param registry the {@link AuthenticationRegistry} to use
     * @throws Exception
     */
    protected void registerAuthentication(AuthenticationRegistry registry) throws Exception {
        this.disableAuthenticationRegistry = true;
    }

    /**
     * Creates the {@link HttpConfiguration} or returns the current instance
     *
     * @return the {@link HttpConfiguration}
     * @throws Exception
     */
    protected final HttpConfiguration getHttp() throws Exception {
        if(http != null) {
            return http;
        }
        AuthenticationManager authenticationManager = authenticationManager();
        authenticationBuilder.parentAuthenticationManager(authenticationManager);
        http = new HttpConfiguration(authenticationBuilder);
        http.setSharedObject(UserDetailsService.class, userDetailsServiceBean());
        if(!disableDefaults) {
            http
                .exceptionHandling().and()
                .sessionManagement().and()
                .securityContext().and()
                .requestCache().and()
                .anonymous().and()
                .servletApi().and()
                .apply(new DefaultLoginPageConfigurator()).and()
                .logout();
        }
        configure(http);
        return http;
    }

    /**
     * Exposes the {@link AuthenticationManager} as a bean
     * @return the {@link AuthenticationManager}
     * @throws Exception
     */
    @Bean(name=BeanIds.AUTHENTICATION_MANAGER)
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return new AuthenticationManagerDelegator(authenticationBuilder);
    }

    /**
     * Gets the {@link AuthenticationManager} to use. The default strategy is if
     * {@link #registerAuthentication(AuthenticationRegistry)} method is
     * overridden to use the {@link AuthenticationRegistry} that was passed in.
     * Otherwise, autowire the {@link AuthenticationManager} by type.
     *
     * @return
     * @throws Exception
     */
    protected AuthenticationManager authenticationManager() throws Exception {
        if(!authenticationManagerInitialized) {
            registerAuthentication(parentAuthenticationRegistry);
            if(disableAuthenticationRegistry) {
                authenticationManager = getBeanExcluding(AuthenticationManager.class, BeanIds.AUTHENTICATION_MANAGER);
            } else {
                authenticationManagerInitialized = true;
                authenticationManager = parentAuthenticationRegistry.build();
            }
            authenticationManagerInitialized = true;
        }
        return authenticationManager;
    }

    /**
     * Exposes the {@link UserDetailsService} as a bean. To override, developers
     * should change {@link #userDetailsService()} instead (this method would be
     * marked final except that the rules for {@link Configuration} forbid it.
     *
     * @return
     * @throws Exception
     * @see {@link #userDetailsService()}
     */
    @Bean(name=BeanIds.USER_DETAILS_SERVICE)
    public UserDetailsService userDetailsServiceBean() throws Exception {
        return userDetailsService();
    }

    /**
     * Allows modifying and accessing the {@link UserDetailsService} from
     * {@link #userDetailsServiceBean()()} without interacting with the
     * {@link ApplicationContext}. Developers should override this method instead of {@link #userDetailsServiceBean()}.
     *
     * @return
     */
    protected UserDetailsService userDetailsService() {
        return parentAuthenticationRegistry.getDefaultUserDetailsService();
    }

    @Override
    public void init(WebSecurityBuilder builder) throws Exception {
        HttpConfiguration http = getHttp();
        FilterSecurityInterceptor securityInterceptor = http.getSharedObject(FilterSecurityInterceptor.class);
        builder
            .addSecurityFilterChainBuilder(http)
            .setSecurityInterceptor(securityInterceptor);

    }

    /**
     * Override this method to configure {@link WebSecurityBuilder}. For
     * example, if you wish to ignore certain requests.
     */
    @Override
    public void configure(WebSecurityBuilder builder) throws Exception {
    }

    /**
     * Gets a bean of a specific type, but excludes the bean name.
     * @param clazz the Class of the bean to look up
     * @param beanNameToExclude the name of the bean to exclude
     * @return the bean or null if it could not be found
     */
    private <T> T getBeanExcluding(Class<T> clazz, String beanNameToExclude) {
        String[] beanNames = context.getBeanNamesForType(clazz);
        if(beanNames.length == 1 && !beanNameToExclude.equals(beanNames[0])) {
            return context.getBean(beanNames[0],clazz);
        }
        if(beanNames.length == 2) {
            if(beanNameToExclude.equals(beanNames[0])) {
                return context.getBean(beanNames[1],clazz);
            }
            if(beanNameToExclude.equals(beanNames[1])) {
                return context.getBean(beanNames[0],clazz);
            }
        }
        return null;
    }

    /**
     * Override this method to configure the {@link HttpConfiguration}
     * @param http
     * @throws Exception
     */
    protected abstract void configure(HttpConfiguration http) throws Exception;

    /**
     * Delays the use of the {@link AuthenticationManager} build from the
     * {@link AuthenticationManagerBuilder} to ensure that it has been fully
     * configured.
     *
     * @author Rob Winch
     * @since 3.2
     */
    static final class AuthenticationManagerDelegator implements AuthenticationManager {
        private AuthenticationManagerBuilder delegateBuilder;
        private AuthenticationManager delegate;
        private final Object delegateMonitor = new Object();

        AuthenticationManagerDelegator(AuthenticationManagerBuilder authentication) {
            this.delegateBuilder = authentication;
        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            if(delegate != null) {
                return delegate.authenticate(authentication);
            }

            synchronized(delegateMonitor) {
                if (delegate == null) {
                    delegate = this.delegateBuilder.getObject();
                    this.delegateBuilder = null;
                }
            }

            return delegate.authenticate(authentication);
        }
    }
}