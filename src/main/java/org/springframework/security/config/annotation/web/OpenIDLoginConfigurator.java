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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.SecurityConfiguratorAdapter;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.openid.AxFetchListFactory;
import org.springframework.security.openid.OpenID4JavaConsumer;
import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationFilter;
import org.springframework.security.openid.OpenIDAuthenticationProvider;
import org.springframework.security.openid.OpenIDAuthenticationToken;
import org.springframework.security.openid.OpenIDConsumer;
import org.springframework.security.openid.RegexBasedAxFetchListFactory;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

/**
 * Adds support for OpenID based authentication.
 *
 * <h2>Example Configuration</h2>
 *
 * <pre>
 *
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
 *
 * 	&#064;Override
 * 	protected void configure(HttpConfiguration http) {
 * 		http
 * 			.authorizeUrls()
 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
 * 				.and()
 * 			.openidLogin()
 * 				.permitAll();
 * 	}
 *
 * 	&#064;Override
 * 	protected void registerAuthentication(
 * 			AuthenticationRegistry authenticationRegistry) throws Exception {
 * 		authenticationRegistry
 * 			.inMemoryAuthentication()
 * 				.withUser(&quot;https://www.google.com/accounts/o8/id?id=lmkCn9xzPdsxVwG7pjYMuDgNNdASFmobNkcRPaWU&quot;)
 * 					.password(&quot;password&quot;)
 * 					.roles(&quot;USER&quot;);
 * 	}
 * }
 * </pre>
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>
 * {@link OpenIDAuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * <ul>
 * <li>
 * {@link HttpConfiguration#authenticationEntryPoint(org.springframework.security.web.AuthenticationEntryPoint)}
 * is populated with a {@link LoginUrlAuthenticationEntryPoint}</li>
 * <li>A {@link OpenIDAuthenticationProvider} is populated into
 * {@link HttpConfiguration#authenticationProvider(org.springframework.security.authentication.AuthenticationProvider)}
 * </li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link HttpConfiguration#authenticationManager()}</li>
 * <li>{@link RememberMeServices} - is optionally used. See
 * {@link RememberMeConfigurator}</li>
 * <li>{@link SessionAuthenticationStrategy} - is optionally used. See
 * {@link SessionManagementConfigurator}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public class OpenIDLoginConfigurator extends SecurityConfiguratorAdapter<DefaultSecurityFilterChain,HttpConfiguration> {
    private OpenIDAuthenticationFilter openIDAuthenticationFilter = new OpenIDAuthenticationFilter();
    private OpenIDConsumer openIDConsumer;
    private ConsumerManager consumerManager;

    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;
    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationEntryPoint authenticationEntryPoint;
    private AuthenticationFailureHandler failureHandler;
    private boolean permitAll;
    private boolean customLoginPage;
    private String loginPage;
    private String loginProcessingUrl;
    private String failureUrl;
    private AuthenticationUserDetailsService<OpenIDAuthenticationToken> authenticationUserDetailsService;
    private List<AttributeExchangeConfigurator> attributeExchangeConfigurators = new ArrayList<AttributeExchangeConfigurator>();

    /**
     * Creates a new instance
     */
    OpenIDLoginConfigurator() {
        loginPage("/login");
        failureUrl("/login?error");
        loginProcessingUrl("/login/openid");
        this.customLoginPage = false;
    }

    /**
     * Sets up OpenID attribute exchange for OpenID's matching the specified
     * pattern.
     *
     * @param identifierPattern
     *            the regular expression for matching on OpenID's (i.e.
     *            "https://www.google.com/.*", ".*yahoo.com.*", etc)
     * @return a {@link AttributeExchangeConfigurator} for further customizations of the attribute exchange
     */
    public AttributeExchangeConfigurator attributeExchange(String identifierPattern) {
        AttributeExchangeConfigurator attributeExchangeConfigurator = new AttributeExchangeConfigurator(identifierPattern);
        this.attributeExchangeConfigurators .add(attributeExchangeConfigurator);
        return attributeExchangeConfigurator;
    }

    /**
     * Allows specifying the {@link OpenIDConsumer} to be used. The default is
     * using an {@link OpenID4JavaConsumer}.
     *
     * @param consumer
     *            the {@link OpenIDConsumer} to be used
     * @return the {@link OpenIDLoginConfigurator} for further customizations
     */
    public OpenIDLoginConfigurator consumer(OpenIDConsumer consumer) {
        this.openIDConsumer = consumer;
        return this;
    }

    /**
     * Allows specifying the {@link ConsumerManager} to be used. If specified,
     * will be populated into an {@link OpenID4JavaConsumer}.
     *
     * <p>
     * This is a shortcut for specifying the {@link OpenID4JavaConsumer} with a
     * specific {@link ConsumerManager} on {@link #consumer(OpenIDConsumer)}.
     * </p>
     *
     * @param consumerManager the {@link ConsumerManager} to use. Cannot be null.
     * @return the {@link OpenIDLoginConfigurator} for further customizations
     */
    public OpenIDLoginConfigurator consumerManager(ConsumerManager consumerManager) {
        this.consumerManager = consumerManager;
        return this;
    }

    /**
     * Specifies the {@link AuthenticationDetailsSource} to use. The default is a {@link WebAuthenticationDetailsSource}.
     *
     * @param authenticationDetailsSource the {@link AuthenticationDetailsSource} to use.
     * @return the {@link OpenIDLoginConfigurator} for further customizations
     */
    public OpenIDLoginConfigurator authenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        return this;
    }

    /**
     * The {@link AuthenticationUserDetailsService} to use. By default a
     * {@link UserDetailsByNameServiceWrapper} is used with the
     * {@link UserDetailsService} shared object found with
     * {@link HttpConfiguration#getSharedObject(Class)}.
     *
     * @param authenticationUserDetailsService the {@link AuthenticationDetailsSource} to use
     * @return the {@link OpenIDLoginConfigurator} for further customizations
     */
    public OpenIDLoginConfigurator authenticationUserDetailsService(AuthenticationUserDetailsService<OpenIDAuthenticationToken> authenticationUserDetailsService) {
        this.authenticationUserDetailsService = authenticationUserDetailsService;
        return this;
    }

    /**
     * Specifies where users will go after authenticating successfully if they
     * have not visited a secured page prior to authenticating. This is a
     * shortcut for calling {@link #defaultSuccessUrl(String)}.
     *
     * @param defaultSuccessUrl
     *            the default success url
     * @return the {@link OpenIDLoginConfigurator} for additional customization
     */
    public OpenIDLoginConfigurator defaultSuccessUrl(String defaultSuccessUrl) {
        return defaultSuccessUrl(defaultSuccessUrl, false);
    }

    /**
     * Specifies where users will go after authenticating successfully if they
     * have not visited a secured page prior to authenticating or
     * {@code alwaysUse} is true. This is a shortcut for calling
     * {@link #successHandler(AuthenticationSuccessHandler)}.
     *
     * @param defaultSuccessUrl
     *            the default success url
     * @param alwaysUse
     *            true if the {@code defaultSuccesUrl} should be used after
     *            authentication despite if a protected page had been previously
     *            visited
     * @return the {@link OpenIDLoginConfigurator} for additional customization
     */
    public OpenIDLoginConfigurator defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
        handler.setDefaultTargetUrl(defaultSuccessUrl);
        handler.setAlwaysUseDefaultTargetUrl(alwaysUse);
        return successHandler(handler);
    }

    /**
     * Specifies the {@link AuthenticationSuccessHandler} to be used. The
     * default is {@link SavedRequestAwareAuthenticationSuccessHandler} with no
     * additional properites set.
     *
     * @param successHandler
     *            the {@link AuthenticationSuccessHandler}.
     * @return the {@link OpenIDLoginConfigurator} for additional customization
     */
    public OpenIDLoginConfigurator successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    /**
     * Specifies the URL used to authenticate OpenID requests. If the {@link HttpServletRequest}
     * matches this URL the {@link OpenIDAuthenticationFilter} will attempt to
     * authenticate the request. The default is "/login/openid".
     *
     * @param loginUrl
     *            the URL used to perform authentication
     * @return the {@link OpenIDLoginConfigurator} for additional customization
     */
    public OpenIDLoginConfigurator loginProcessingUrl(String loginProcessingUrl) {
        this.loginProcessingUrl = loginProcessingUrl;
        openIDAuthenticationFilter.setFilterProcessesUrl(loginProcessingUrl);
        return this;
    }

    /**
     * <p>
     * Specifies the URL to send users to if login is required. If used with
     * {@link WebSecurityConfigurerAdapter} a default login page will be
     * generated when this attribute is not specified.
     * </p>
     *
     * <p>
     * If a URL is specified or this is not being used in conjuction with
     * {@link WebSecurityConfigurerAdapter}, users are required to process the
     * specified URL to generate a login page. In general, the login page should
     * create a form that submits a request with the following requirements to
     * work with {@link UsernamePasswordAuthenticationFilter}:
     * </p>
     *
     * <ul>
     * <li>It must be an HTTP POST</li>
     * <li>It must be submitted to {@link #loginProcessingUrl(String)}</li>
     * <li>It should include the OpenID as an HTTP parameter by the name of
     * {@link OpenIDAuthenticationFilter#DEFAULT_CLAIMED_IDENTITY_FIELD}</li>
     * <li>It should include the password as an HTTP parameter by the name of
     * {@link #passwordParameter(String)}</li>
     * </ul>
     *
     * @param loginPage the login page to redirect to if authentication is required (i.e. "/login")
     * @return the {@link FormLoginConfigurator} for additional customization
     */
    public OpenIDLoginConfigurator loginPage(String loginPage) {
        this.loginPage = loginPage;
        this.authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(loginPage);
        this.customLoginPage = true;
        return this;
    }

    /**
     * Equivalent of invoking permitAll(true)
     * @return the {@link OpenIDLoginConfigurator} for further customization
     */
    public OpenIDLoginConfigurator permitAll() {
        return permitAll(true);
    }

    /**
     * Ensures the urls for {@link #failureUrl(String)} and
     * {@link #loginUrl(String)} are granted access to any user.
     *
     * @param permitAll
     *            true if access should be granted to the URLs, false if nothing
     *            additional should be done
     * @return the {@link OpenIDLoginConfigurator} for further customization
     */
    public OpenIDLoginConfigurator permitAll(boolean permitAll) {
        this.permitAll = permitAll;
        return this;
    }

    /**
     * Specifies the URL to redirect to when authentication fails. This is a shortcut
     * for invoking {@link #failureHandler(AuthenticationFailureHandler)} with a
     * {@link SimpleUrlAuthenticationFailureHandler}. The default is "/login?error".
     *
     * @param failureUrl the URL to redirect to when authentication fails.
     * @return the {@link OpenIDLoginConfigurator} for further customization
     */
    public OpenIDLoginConfigurator failureUrl(String failureUrl) {
        this.failureUrl = failureUrl;
        return failureHandler(new SimpleUrlAuthenticationFailureHandler(failureUrl));
    }

    /**
     * Specifies the {@link AuthenticationFailureHandler} to use when authentication fails. The default is to redirect to "/login?error".
     * @param failureHandler the {@link AuthenticationFailureHandler} to use
     * @return the {@link OpenIDLoginConfigurator} for further customization
     */
    public OpenIDLoginConfigurator failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    @Override
    public void init(HttpConfiguration http) throws Exception {
        if(permitAll) {
            PermitAllSupport.permitAll(http, loginPage, loginProcessingUrl, failureUrl);
        }
        http.authenticationEntryPoint(authenticationEntryPoint);

        OpenIDAuthenticationProvider authenticationProvider = new OpenIDAuthenticationProvider();
        authenticationProvider.setAuthenticationUserDetailsService(getAuthenticationUserDetailsService(http));
        http.authenticationProvider(authenticationProvider);
    }

    @Override
    public void configure(HttpConfiguration http) throws Exception {
        openIDAuthenticationFilter.setAuthenticationManager(http.authenticationManager());
        openIDAuthenticationFilter.setAuthenticationSuccessHandler(successHandler);
        openIDAuthenticationFilter.setAuthenticationFailureHandler(failureHandler);
        openIDAuthenticationFilter.setConsumer(getConsumer());
        if(authenticationDetailsSource != null) {
            openIDAuthenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
        }
        SessionAuthenticationStrategy sessionAuthenticationStrategy = http.getSharedObject(SessionAuthenticationStrategy.class);
        if(sessionAuthenticationStrategy != null) {
            openIDAuthenticationFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if(rememberMeServices != null) {
            openIDAuthenticationFilter.setRememberMeServices(rememberMeServices);
        }
        openIDAuthenticationFilter.afterPropertiesSet();

        http.addFilter(openIDAuthenticationFilter);
    }

    String getLoginProcessingUrl() {
        return this.loginProcessingUrl;
    }

    String getLoginPage() {
        return this.loginPage;
    }

    String getFailureUrl() {
        return this.failureUrl;
    }

    boolean isCustomLoginPage() {
        return customLoginPage;
    }

    /**
     * Gets the {@link OpenIDConsumer} that was configured or defaults to an {@link OpenID4JavaConsumer}.
     * @return the {@link OpenIDConsumer} to use
     * @throws ConsumerException
     */
    private OpenIDConsumer getConsumer() throws ConsumerException {
        if(openIDConsumer == null) {
            openIDConsumer = new OpenID4JavaConsumer(getConsumerManager(), attributesToFetchFactory());
        }
        return openIDConsumer;
    }

    /**
     * Gets the {@link ConsumerManager} that was configured or defaults to using a {@link ConsumerManager} with the default constructor.
     * @return the {@link ConsumerManager} to use
     */
    private ConsumerManager getConsumerManager() {
        if(this.consumerManager != null) {
            return this.consumerManager;
        }
        return new ConsumerManager();
    }

    /**
     * Creates an {@link RegexBasedAxFetchListFactory} using the attributes
     * populated by {@link AttributeExchangeConfigurator}
     *
     * @return the {@link AxFetchListFactory} to use
     */
    private AxFetchListFactory attributesToFetchFactory() {
        Map<String,List<OpenIDAttribute>> identityToAttrs = new HashMap<String,List<OpenIDAttribute>>();
        for(AttributeExchangeConfigurator conf : attributeExchangeConfigurators) {
            identityToAttrs.put(conf.identifier, conf.getAttributes());
        }
        return new RegexBasedAxFetchListFactory(identityToAttrs);
    }

    /**
     * Gets the {@link AuthenticationUserDetailsService} that was configured or
     * defaults to {@link UserDetailsByNameServiceWrapper} that uses a
     * {@link UserDetailsService} looked up using
     * {@link HttpConfiguration#getSharedObject(Class)}
     *
     * @param http the current {@link HttpConfiguration}
     * @return the {@link AuthenticationUserDetailsService}.
     */
    private AuthenticationUserDetailsService<OpenIDAuthenticationToken> getAuthenticationUserDetailsService(
            HttpConfiguration http) {
        if(authenticationUserDetailsService != null) {
            return authenticationUserDetailsService;
        }
        return new UserDetailsByNameServiceWrapper<OpenIDAuthenticationToken>(http.getSharedObject(UserDetailsService.class));
    }

    /**
     * A class used to add OpenID attributes to look up
     *
     * @author Rob Winch
     */
    public class AttributeExchangeConfigurator {
        private final String identifier;
        private List<OpenIDAttribute> attributes = new ArrayList<OpenIDAttribute>();
        private List<AttributeConfigurator> attributeConfigurators = new ArrayList<AttributeConfigurator>();

        /**
         * Creates a new instance
         * @param identifierPattern the pattern that attempts to match on the OpenID
         * @see OpenIDLoginConfigurator#attributeExchange(String)
         */
        private AttributeExchangeConfigurator(String identifierPattern) {
            this.identifier = identifierPattern;
        }

        /**
         * Get the {@link OpenIDLoginConfigurator} to customize the OpenID configuration further
         * @return the {@link OpenIDLoginConfigurator}
         */
        public OpenIDLoginConfigurator and() {
            return OpenIDLoginConfigurator.this;
        }

        /**
         * Adds an {@link OpenIDAttribute} to be obtained for the configured OpenID pattern.
         * @param attribute the {@link OpenIDAttribute} to obtain
         * @return the {@link AttributeExchangeConfigurator} for further customization of attribute exchange
         */
        public AttributeExchangeConfigurator attribute(OpenIDAttribute attribute) {
            this.attributes.add(attribute);
            return this;
        }

        /**
         * Adds an {@link OpenIDAttribute} with the given name
         * @param name the name of the {@link OpenIDAttribute} to create
         * @return an {@link AttributeConfigurator} to further configure the {@link OpenIDAttribute} that should be obtained.
         */
        public AttributeConfigurator attribute(String name) {
            AttributeConfigurator attributeConfigurator = new AttributeConfigurator(name);
            this.attributeConfigurators.add(attributeConfigurator);
            return attributeConfigurator;
        }

        /**
         * Gets the {@link OpenIDAttribute}'s for the configured OpenID pattern
         * @return
         */
        private List<OpenIDAttribute> getAttributes() {
            for(AttributeConfigurator config : attributeConfigurators) {
                attributes.add(config.build());
            }
            attributeConfigurators.clear();
            return attributes;
        }

        /**
         * Configures an {@link OpenIDAttribute}
         *
         * @author Rob Winch
         * @since 3.2
         */
        public class AttributeConfigurator {
            private String name;
            private int count = 1;
            private boolean required = false;
            private String type;

            /**
             * Creates a new instance
             * @param name the name of the attribute
             * @see AttributeExchangeConfigurator#attribute(String)
             */
            private AttributeConfigurator(String name) {
                this.name = name;
            }

            /**
             * Specifies the number of attribute values to request. Default is 1.
             * @param count the number of attributes to request.
             * @return the {@link AttributeConfigurator} for further customization
             */
            public AttributeConfigurator count(int count) {
                this.count = count;
                return this;
            }

            /**
             * Specifies that this attribute is required. The default is
             * <code>false</code>. Note that as outlined in the OpenID
             * specification, required attributes are not validated by the
             * OpenID Provider. Developers should perform any validation in
             * custom code.
             *
             * @param required specifies the attribute is required
             * @return the {@link AttributeConfigurator} for further customization
             */
            public AttributeConfigurator required(boolean required) {
                this.required = required;
                return this;
            }

            /**
             * The OpenID attribute type.
             * @param type
             * @return
             */
            public AttributeConfigurator type(String type) {
                this.type = type;
                return this;
            }

            /**
             * Gets the {@link AttributeExchangeConfigurator} for further
             * customization of the attributes
             *
             * @return the {@link AttributeConfigurator}
             */
            public AttributeExchangeConfigurator and() {
                return AttributeExchangeConfigurator.this;
            }

            /**
             * Builds the {@link OpenIDAttribute}.
             * @return
             */
            private OpenIDAttribute build() {
                OpenIDAttribute attribute = new OpenIDAttribute(name, type);
                attribute.setCount(count);
                attribute.setRequired(required);
                return attribute;
            }
        }
    }
}
