/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
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
import org.springframework.security.config.annotation.AbstractSecurityConfigurator;
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
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class OpenIDLoginConfigurator extends AbstractSecurityConfigurator<DefaultSecurityFilterChain,HttpConfigurator> {
    private OpenIDAuthenticationFilter openIDAuthenticationFilter = new OpenIDAuthenticationFilter();
    private OpenIDConsumer openIDConsumer;
    private ConsumerManager consumerManager;

    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;
    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationEntryPoint authenticationEntryPoint;
    private AuthenticationFailureHandler failureHandler;
    private boolean permitAll;
    private String loginPage;
    private String loginProcessingUrl;
    private String failureUrl;
    private AuthenticationUserDetailsService<OpenIDAuthenticationToken> authenticationUserDetailsService;
    private List<AttributeExchangeConfigurator> attributeExchangeConfigurators = new ArrayList<AttributeExchangeConfigurator>();

    public OpenIDLoginConfigurator() {
        loginUrl("/login");
        failureUrl("/login?error");
        loginProcessingUrl("/login/openid");
    }

    protected void doInit(HttpConfigurator http) throws Exception {
        if(permitAll) {
            PermitAllSupport.permitAll(http, loginPage, loginProcessingUrl, failureUrl);
        }
        http.authenticationEntryPoint(authenticationEntryPoint);

        OpenIDAuthenticationProvider authenticationProvider = new OpenIDAuthenticationProvider();
        authenticationProvider.setAuthenticationUserDetailsService(authenticationUserDetailsService(http));
        http.authenticationProvider(authenticationProvider);
    }

    public AttributeExchangeConfigurator attributeExchange(String identifierPattern) {
        AttributeExchangeConfigurator attributeExchangeConfigurator = new AttributeExchangeConfigurator(identifierPattern);
        this.attributeExchangeConfigurators .add(attributeExchangeConfigurator);
        return attributeExchangeConfigurator;
    }

    public class AttributeExchangeConfigurator {
        private String identifier;
        private List<OpenIDAttribute> attributes = new ArrayList<OpenIDAttribute>();
        private List<AttributeConfigurator> attributeConfigurators = new ArrayList<AttributeConfigurator>();

        private AttributeExchangeConfigurator(String identifierPattern) {
            this.identifier = identifierPattern;
        }

        public OpenIDLoginConfigurator and() {
            return OpenIDLoginConfigurator.this;
        }

        public AttributeExchangeConfigurator attribute(OpenIDAttribute attribute) {
            this.attributes.add(attribute);
            return this;
        }

        public AttributeConfigurator attribute(String name) {
            AttributeConfigurator attributeConfigurator = new AttributeConfigurator(name);
            this.attributeConfigurators.add(attributeConfigurator);
            return attributeConfigurator;
        }

        private List<OpenIDAttribute> getAttributes() {
            for(AttributeConfigurator config : attributeConfigurators) {
                attributes.add(config.build());
            }
            attributeConfigurators.clear();
            return attributes;
        }

        public class AttributeConfigurator {
            private String name;
            private int count = 1;
            private boolean required = false;
            private String type;

            private AttributeConfigurator(String name) {
                this.name = name;
            }

            public AttributeConfigurator count(int count) {
                this.count = count;
                return this;
            }

            public AttributeConfigurator required(boolean required) {
                this.required = required;
                return this;
            }

            public AttributeConfigurator type(String type) {
                this.type = type;
                return this;
            }

            private OpenIDAttribute build() {
                OpenIDAttribute attribute = new OpenIDAttribute(name, type);
                attribute.setCount(count);
                attribute.setRequired(required);
                return attribute;
            }

            public AttributeExchangeConfigurator and() {
                return AttributeExchangeConfigurator.this;
            }
        }
    }

    /**
     * @param http
     * @return
     */
    private AuthenticationUserDetailsService<OpenIDAuthenticationToken> authenticationUserDetailsService(
            HttpConfigurator http) {
        if(authenticationUserDetailsService != null) {
            return authenticationUserDetailsService;
        }
        return new UserDetailsByNameServiceWrapper<OpenIDAuthenticationToken>(http.getSharedObject(UserDetailsService.class));
    }

    protected void doConfigure(HttpConfigurator http) throws Exception {
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

        // FIXME should be able to add OpenIDFilter w/out specifying class
        http.addFilterBefore(openIDAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }

    private OpenIDConsumer getConsumer() throws ConsumerException {
        if(openIDConsumer == null) {
            openIDConsumer = new OpenID4JavaConsumer(consumerManager(), attributesToFetchFactory());
        }
        return openIDConsumer;
    }

    private ConsumerManager consumerManager() {
        if(this.consumerManager != null) {
            return this.consumerManager;
        }
        return new ConsumerManager();
    }

    private AxFetchListFactory attributesToFetchFactory() {
        Map<String,List<OpenIDAttribute>> identityToAttrs = new HashMap<String,List<OpenIDAttribute>>();
        for(AttributeExchangeConfigurator conf : attributeExchangeConfigurators) {
            identityToAttrs.put(conf.identifier, conf.getAttributes());
        }
        return new RegexBasedAxFetchListFactory(identityToAttrs);
    }

    public OpenIDLoginConfigurator consumer(OpenIDConsumer consumer) {
        this.openIDConsumer = consumer;
        return this;
    }

    public OpenIDLoginConfigurator consumerManager(ConsumerManager consumerManager) {
        this.consumerManager = consumerManager;
        return this;
    }

    public OpenIDLoginConfigurator authenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        return this;
    }

    public OpenIDLoginConfigurator authenticationUserDetailsService(AuthenticationUserDetailsService<OpenIDAuthenticationToken> authenticationUserDetailsService) {
        this.authenticationUserDetailsService = authenticationUserDetailsService;
        return this;
    }

    public OpenIDLoginConfigurator defaultSuccessUrl(String defaultSuccessUrl) {
        return defaultSuccessUrl(defaultSuccessUrl, false);
    }

    public OpenIDLoginConfigurator defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
        handler.setDefaultTargetUrl(defaultSuccessUrl);
        handler.setAlwaysUseDefaultTargetUrl(alwaysUse);
        return successHandler(handler);
    }

    public OpenIDLoginConfigurator successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    /**
     * Specifies the URL used to log in. If the request is an HTTP POST, the
     * {@link UsernamePasswordAuthenticationFilter} will attempt to authenicate
     * the request. Otherwise, the user will be sent to the login form.
     *
     * @param loginUrl
     * @return
     */
    public OpenIDLoginConfigurator loginUrl(String loginUrl) {
        loginProcessingUrl(loginUrl);
        return loginPage(loginUrl);
    }

    public OpenIDLoginConfigurator loginProcessingUrl(String loginProcessingUrl) {
        this.loginProcessingUrl = loginProcessingUrl;
        openIDAuthenticationFilter.setFilterProcessesUrl(loginProcessingUrl);
        return this;
    }

    public OpenIDLoginConfigurator loginPage(String loginPage) {
        this.loginPage = loginPage;
        this.authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(loginPage);
        return this;
    }

    /**
     * Equivalent of invoking permitAll(true)
     * @return
     */
    public OpenIDLoginConfigurator permitAll() {
        return permitAll(true);
    }

    /**
     * Ensures the urls for {@link #failureUrl(String)} and
     * {@link #loginUrl(String)} are granted access to any user.
     *
     * @param permitAll
     * @return
     */
    public OpenIDLoginConfigurator permitAll(boolean permitAll) {
        this.permitAll = permitAll;
        return this;
    }

    public OpenIDLoginConfigurator failureUrl(String failureUrl) {
        this.failureUrl = failureUrl;
        return failureHandler(new SimpleUrlAuthenticationFailureHandler(failureUrl));
    }

    public OpenIDLoginConfigurator failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }
}
