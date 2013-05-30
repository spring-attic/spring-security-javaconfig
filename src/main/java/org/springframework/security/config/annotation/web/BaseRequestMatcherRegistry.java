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
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.http.HttpMethod;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.config.annotation.SecurityConfiguratorAdapter;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.web.util.RequestMatchers;
import org.springframework.security.web.util.RequestMatcher;

/**
 * A base class for registering {@link RequestMatcher}'s. For example, it might allow for specifying which
 * {@link RequestMatcher} require a certain level of authorization.
 *
 * @author Rob Winch
 * @since 3.2
 *
 * @param <C> The object that is returned or Chained after creating the RequestMatcher
 * @param <O> The Object being built by Builder B
 * @param <B> The Builder that is building Object O and is configured by this {@link BaseRequestMatcherRegistry}
 *
 * @see ChannelSecurityFilterConfigurator
 * @see UrlAuthorizations
 * @see ExpressionUrlAuthorizations
 */
abstract class BaseRequestMatcherRegistry<C,O,B extends SecurityBuilder<O>> extends SecurityConfiguratorAdapter<O,B> {
    private List<UrlMapping> urlMappings = new ArrayList<UrlMapping>();

    /**
     * Maps a {@link List} of {@link org.springframework.security.web.util.AntPathRequestMatcher} instances.
     *
     * @param method the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
     * @param antPatterns the ant patterns to create {@link org.springframework.security.web.util.AntPathRequestMatcher}
     *                    from
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C antMatchers(HttpMethod method, String... antPatterns) {
        return chainRequestMatchers(RequestMatchers.antMatchers(method, antPatterns));
    }

    /**
     * Maps a {@link List} of {@link org.springframework.security.web.util.AntPathRequestMatcher} instances that do
     * not care which {@link HttpMethod} is used.
     *
     * @param antPatterns the ant patterns to create {@link org.springframework.security.web.util.AntPathRequestMatcher}
     *                    from
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C antMatchers(String... antPatterns) {
        return chainRequestMatchers(RequestMatchers.antMatchers(antPatterns));
    }

    /**
     * Maps a {@link List} of {@link org.springframework.security.web.util.RegexRequestMatcher} instances.
     *
     * @param method the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
     * @param regexPatterns the regular expressions to create
     *                      {@link org.springframework.security.web.util.RegexRequestMatcher} from
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C regexMatchers(HttpMethod method, String... regexPatterns) {
        return chainRequestMatchers(RequestMatchers.regexMatchers(method,
                regexPatterns));
    }

    /**
     * Create a {@link List} of {@link org.springframework.security.web.util.RegexRequestMatcher} instances that do not
     * specify an {@link HttpMethod}.
     *
     * @param regexPatterns the regular expressions to create
     *                      {@link org.springframework.security.web.util.RegexRequestMatcher} from
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C regexMatchers(String... regexPatterns) {
        return chainRequestMatchers(RequestMatchers.regexMatchers(regexPatterns));
    }

    /**
     * Associates a list of {@link RequestMatcher} instances with the {@link BaseRequestMatcherRegistry}
     *
     * @param requestMatchers the {@link RequestMatcher} instances
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C requestMatchers(RequestMatcher... requestMatchers) {
        return chainRequestMatchers(Arrays.asList(requestMatchers));
    }

    /**
     * Subclasses should implement this method for returning the object that is chained to the creation of the
     * {@link RequestMatcher} instances.
     *
     * @param requestMatchers the {@link RequestMatcher} instances that were created
     * @return the chained Object for the subclass which allows association of something else to the
     *         {@link RequestMatcher}
     */
    abstract C chainRequestMatchers(List<RequestMatcher> requestMatchers);

    /**
     * Gets the {@link UrlMapping} added by subclasses in {@link #chainRequestMatchers(java.util.List)}. May be empty.
     *
     * @return the {@link UrlMapping} added by subclasses in {@link #chainRequestMatchers(java.util.List)}
     */
    final List<UrlMapping> getUrlMappings() {
        return urlMappings;
    }

    /**
     * Adds a {@link UrlMapping} added by subclasses in {@link #chainRequestMatchers(java.util.List)}.
     * @param urlMapping {@link UrlMapping} the mapping to add
     */
    final void addMapping(UrlMapping urlMapping) {
        this.urlMappings.add(urlMapping);
    }

    /**
     * Adds a {@link UrlMapping} added by subclasses in {@link #chainRequestMatchers(java.util.List)} at a particular
     * index.
     *
     * @param index the index to add a {@link UrlMapping}
     * @param urlMapping {@link UrlMapping} the mapping to add
     */
    final void addMapping(int index, UrlMapping urlMapping) {
        this.urlMappings.add(index, urlMapping);
    }

    /**
     * Creates the mapping of {@link RequestMatcher} to {@link Collection} of {@link ConfigAttribute} instances
     *
     * @return the mapping of {@link RequestMatcher} to {@link Collection} of {@link ConfigAttribute} instances. Cannot
     *         be null.
     */
    final LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> createRequestMap() {
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
        for (UrlMapping mapping : getUrlMappings()) {
            requestMap.put(mapping.getRequestMatcher(),
                    mapping.getConfigAttrs());
        }
        return requestMap;
    }

    /**
     * A mapping of {@link RequestMatcher} to {@link Collection} of {@link ConfigAttribute} instances
     */
    static final class UrlMapping {
        private RequestMatcher requestMatcher;
        private Collection<ConfigAttribute> configAttrs;

        UrlMapping(RequestMatcher requestMatcher,
                Collection<ConfigAttribute> configAttrs) {
            this.requestMatcher = requestMatcher;
            this.configAttrs = configAttrs;
        }

        public RequestMatcher getRequestMatcher() {
            return requestMatcher;
        }

        public Collection<ConfigAttribute> getConfigAttrs() {
            return configAttrs;
        }
    }
}
