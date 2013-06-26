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
package org.springframework.security.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.web.HttpBuilder;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;


/**
 * Adds URL based authorization using {@link DefaultFilterInvocationSecurityMetadataSource}. At least one
 * {@link org.springframework.web.bind.annotation.RequestMapping} needs to be mapped to {@link ConfigAttribute}'s for
 * this {@link SecurityContextConfigurer} to have meaning.
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 *     <li>{@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated to allow other {@link org.springframework.security.config.annotation.SecurityConfigurer}'s to customize:
 * <ul>
 *     <li>{@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 *     <li>{@link org.springframework.security.config.annotation.web.builders.HttpConfiguration#authenticationManager()}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 * @see ExpressionUrlAuthorizations
 */
public final class UrlAuthorizations<H extends HttpBuilder<H>> extends BaseInterceptUrlConfigurer<UrlAuthorizations<H>.AuthorizedUrl,H> {

    /**
     * Creates the default {@link AccessDecisionVoter} instances used if an
     * {@link AccessDecisionManager} was not specified using
     * {@link #accessDecisionManager(AccessDecisionManager)}.
     */
    @Override
    @SuppressWarnings("rawtypes")
    final List<AccessDecisionVoter> decisionVoters() {
        List<AccessDecisionVoter> decisionVoters = new ArrayList<AccessDecisionVoter>();
        decisionVoters.add(new RoleVoter());
        decisionVoters.add(new AuthenticatedVoter());
        return decisionVoters;
    }

    /**
     * Creates the {@link FilterInvocationSecurityMetadataSource} to use. The
     * implementation is a {@link DefaultFilterInvocationSecurityMetadataSource}
     * .
     */
    @Override
    FilterInvocationSecurityMetadataSource createMetadataSource() {
        return new DefaultFilterInvocationSecurityMetadataSource(createRequestMap());
    }

    /**
     * Chains the {@link RequestMatcher} creation to the {@link AuthorizedUrl} class.
     */
    @Override
    protected AuthorizedUrl chainRequestMatchers(List<RequestMatcher> requestMatchers) {
        return new AuthorizedUrl(requestMatchers);
    }

    /**
     * Adds a mapping of the {@link RequestMatcher} instances to the {@link ConfigAttribute} instances.
     * @param requestMatchers the {@link RequestMatcher} instances that should map to the provided {@link ConfigAttribute} instances
     * @param configAttributes the {@link ConfigAttribute} instances that should be mapped by the {@link RequestMatcher} instances
     * @return the {@link UrlAuthorizations} for further customizations
     */
    private UrlAuthorizations<H> addMapping(Iterable<? extends RequestMatcher> requestMatchers, Collection<ConfigAttribute> configAttributes) {
        for(RequestMatcher requestMatcher : requestMatchers) {
            addMapping(new UrlMapping(requestMatcher, configAttributes));
        }
        return this;
    }

    /**
     * Creates a String for specifying a user requires a role.
     *
     * @param role
     *            the role that should be required which is prepended with ROLE_
     *            automatically (i.e. USER, ADMIN, etc). It should not start
     *            with ROLE_
     * @return the {@link ConfigAttribute} expressed as a String
     */
    private static String hasRole(String role) {
        Assert.isTrue(
                !role.startsWith("ROLE_"),
                role
                        + " should not start with ROLE_ since ROLE_ is automatically prepended when using hasRole. Consider using hasAuthority or access instead.");
        return "ROLE_" + role;
    }

    /**
     * Creates a String for specifying that a user requires one of many roles.
     *
     * @param roles
     *            the roles that the user should have at least one of (i.e.
     *            ADMIN, USER, etc). Each role should not start with ROLE_ since
     *            it is automatically prepended already.
     * @return the {@link ConfigAttribute} expressed as a String
     */
    private static String[] hasAnyRole(String... roles) {
        for(int i=0;i<roles.length;i++) {
            roles[i] = "ROLE_" + roles[i];
        }
        return roles;
    }

    /**
     * Creates a String for specifying that a user requires one of many authorities
     * @param authorities the authorities that the user should have at least one of (i.e. ROLE_USER, ROLE_ADMIN, etc).
     * @return the {@link ConfigAttribute} expressed as a String.
     */
    private static String[] hasAnyAuthority(String... authorities) {
        return authorities;
    }

    /**
     * Maps the specified {@link RequestMatcher} instances to {@link ConfigAttribute} instances.
     *
     * @author Rob Winch
     * @since 3.2
     */
    public final class AuthorizedUrl {
        private final List<RequestMatcher> requestMatchers;

        /**
         * Creates a new instance
         * @param requestMatchers the {@link RequestMatcher} instances to map to some {@link ConfigAttribute} instances.
         * @see UrlAuthorizations#chainRequestMatchers(List)
         */
        private AuthorizedUrl(List<RequestMatcher> requestMatchers) {
            Assert.notEmpty(requestMatchers, "requestMatchers must contain at least one value");
            this.requestMatchers = requestMatchers;
        }

        /**
         * Specifies a user requires a role.
         *
         * @param role
         *            the role that should be required which is prepended with ROLE_
         *            automatically (i.e. USER, ADMIN, etc). It should not start
         *            with ROLE_
         * the {@link UrlAuthorizations} for further customization
         */
        public UrlAuthorizations<H> hasRole(String role) {
            return access(UrlAuthorizations.hasRole(role));
        }

        /**
         * Specifies that a user requires one of many roles.
         *
         * @param roles
         *            the roles that the user should have at least one of (i.e.
         *            ADMIN, USER, etc). Each role should not start with ROLE_ since
         *            it is automatically prepended already.
         * @return the {@link UrlAuthorizations} for further customization
         */
        public UrlAuthorizations<H> hasAnyRole(String... roles) {
            return access(UrlAuthorizations.hasAnyRole(roles));
        }

        /**
         * Specifies a user requires an authority.
         *
         * @param authority
         *            the authority that should be required
         * @return the {@link UrlAuthorizations} for further customization
         */
        public UrlAuthorizations<H> hasAuthority(String authority) {
            return access(authority);
        }

        /**
         * Specifies that a user requires one of many authorities
         * @param authorities the authorities that the user should have at least one of (i.e. ROLE_USER, ROLE_ADMIN, etc).
         * @return the {@link UrlAuthorizations} for further customization
         */
        public UrlAuthorizations<H> hasAnyAuthority(String... authorities) {
            return access(UrlAuthorizations.hasAnyAuthority(authorities));
        }

        /**
         * Specifies that an anonymous user is allowed access
         * @return the {@link UrlAuthorizations} for further customization
         */
        public UrlAuthorizations<H> anonymous() {
            return hasRole("ROLE_ANONYMOUS");
        }

        /**
         * Specifies that the user must have the specified {@link ConfigAttribute}'s
         * @param attributes the {@link ConfigAttribute}'s that restrict access to a URL
         * @return the {@link UrlAuthorizations} for further customization
         */
        public UrlAuthorizations<H> access(String... attributes) {
            addMapping(requestMatchers, SecurityConfig.createList(attributes));
            return UrlAuthorizations.this;
        }
    }
}