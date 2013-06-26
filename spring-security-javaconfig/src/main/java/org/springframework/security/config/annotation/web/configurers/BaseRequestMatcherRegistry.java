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
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherConfigurer;
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
 * @see ChannelSecurityConfigurer
 * @see UrlAuthorizations
 * @see ExpressionUrlAuthorizations
 */
public abstract class BaseRequestMatcherRegistry<C,O,B extends SecurityBuilder<O>> extends AbstractRequestMatcherConfigurer<C,O,B> {
    private List<UrlMapping> urlMappings = new ArrayList<UrlMapping>();

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

