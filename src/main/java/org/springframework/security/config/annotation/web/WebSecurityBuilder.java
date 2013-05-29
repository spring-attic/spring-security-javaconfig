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
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * <p>
 * The {@link WebSecurityBuilder} is created by {@link WebSecurityConfiguration}
 * to create the {@link FilterChainProxy} known as the Spring Security Filter
 * Chain (springSecurityFilterChain). The springSecurityFilterChain is the
 * {@link Filter} that the {@link DelegatingFilterProxy} delegates to.
 * </p>
 *
 * <p>
 * Customizations to the {@link WebSecurityBuilder} can be made by creating a
 * {@link WebSecurityConfigurer} or more likely by overriding
 * {@link WebSecurityConfigurerAdapter}.
 * </p>
 *
 * @see EnableWebSecurity
 * @see WebSecurityConfiguration
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class WebSecurityBuilder extends AbstractConfiguredSecurityBuilder<FilterChainProxy, WebSecurityBuilder> {
    private List<RequestMatcher> ignoredRequests = new ArrayList<RequestMatcher>();
    private List<HttpConfiguration> httpBuilders = new ArrayList<HttpConfiguration>();
    private FilterSecurityInterceptor filterSecurityInterceptor;
    private HttpFirewall httpFirewall;
    private final IgnoredRequestRegistry ignoredRequestRegistry = new IgnoredRequestRegistry();

    /**
     * Creates a new instance
     * @see WebSecurityConfiguration
     */
    WebSecurityBuilder() {
    }

    /**
     * <p>
     * Allows adding {@link RequestMatcher} instances that should that Spring
     * Security should ignore. Typically the requests that are registered should
     * be that of only static resources. For requests that are dynamic, consider
     * mapping the request to allow all users instead.
     * </p>
     *
     * <p>
     * Web Security provided by Spring Security (including the
     * {@link SecurityContext}) will not be available on
     * {@link HttpServletRequest} that match.
     * </p>
     *
     * Example Usage:
     *
     * <pre>
     * 	webSecurityBuilder
     * 		.ignoring()
     * 			// ignore all URLs that start with /resources/
     * 			.antMatchers("/resources/**);
     * </pre>
     *
     * @return the {@link IgnoredRequestRegistry} to use for registering request
     *         that should be ignored
     */
    public IgnoredRequestRegistry ignoring() {
        return ignoredRequestRegistry;
    }

    /**
     * Allows customizing the {@link HttpFirewall}. The default is
     * {@link DefaultHttpFirewall}.
     *
     * @param httpFirewall the custom {@link HttpFirewall}
     * @return the {@link WebSecurityBuilder} for further customizations
     */
    public WebSecurityBuilder httpFirewall(HttpFirewall httpFirewall) {
        this.httpFirewall = httpFirewall;
        return this;
    }

    /**
     * <p>
     * Adds builders to create {@link SecurityFilterChain} instances.
     * </p>
     *
     * <p>
     * Typically this method is invoked automatically within the framework from
     * {@link WebSecurityConfigurerAdapter#init(WebSecurityBuilder)}
     * </p>
     *
     * @param securityFilterChainBuilder
     *            the builder to use to create the {@link SecurityFilterChain}
     *            instances
     * @return the {@link WebSecurityBuilder} for further customizations
     */
    public WebSecurityBuilder addSecurityFilterChainBuilder(HttpConfiguration securityFilterChainBuilder) {
        this.httpBuilders.add(securityFilterChainBuilder);
        return this;
    }

    @Override
    protected FilterChainProxy performBuild() throws Exception {
        Assert.state(!httpBuilders.isEmpty(), "At least one SecurityFilterBuilder needs to be specified. Invoke FilterChainProxyBuilder.securityFilterChains");
        int chainSize = ignoredRequests.size() + httpBuilders.size();
        List<SecurityFilterChain> securityFilterChains = new ArrayList<SecurityFilterChain>(chainSize);
        for(RequestMatcher ignoredRequest : ignoredRequests) {
            securityFilterChains.add(new DefaultSecurityFilterChain(ignoredRequest));
        }
        for(HttpConfiguration http : httpBuilders) {
            securityFilterChains.add(http.build());
            this.filterSecurityInterceptor = http.getSharedObject(FilterSecurityInterceptor.class);
        }
        FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);
        if(httpFirewall != null) {
            filterChainProxy.setFirewall(httpFirewall);
        }
        return filterChainProxy;
    }

    /**
     * Gets one of the {@link FilterSecurityInterceptor} for the {@link HttpConfiguration} injected. May be null.
     * @return a {@link FilterSecurityInterceptor}
     */
    FilterSecurityInterceptor getSecurityInterceptor() {
        return filterSecurityInterceptor;
    }

    /**
     * Allows registering {@link RequestMatcher} instances that should be
     * ignored by Spring Security.
     *
     * @author Rob Winch
     * @since 3.2
     */
    public final class IgnoredRequestRegistry extends BaseRequestMatcherRegistry<IgnoredRequestRegistry,FilterChainProxy,WebSecurityBuilder> {

        @Override
        IgnoredRequestRegistry chainRequestMatchers(List<RequestMatcher> requestMatchers) {
            ignoredRequests.addAll(requestMatchers);
            return this;
        }

        /**
         * Returns the {@link WebSecurityBuilder} to be returned for chaining.
         */
        @Override
        public WebSecurityBuilder and() {
            return WebSecurityBuilder.this;
        }

        private IgnoredRequestRegistry(){}
    }
}
