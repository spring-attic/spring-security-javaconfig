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
import org.springframework.security.config.annotation.web.util.RequestMatchers;
import org.springframework.security.web.util.RequestMatcher;

/**
 *
 * @author Rob Winch
 *
 * @param <C> The object that is returned or Chained after creating the RequestMatcher
 * @param <O> The Object being built by Builder B
 * @param <B> The Builder that is building Object O
 */
abstract class BaseRequestMatcherRegistry<C,O,B extends SecurityBuilder<O>> extends SecurityConfiguratorAdapter<O,B> {
    private List<UrlMapping> urlMappings = new ArrayList<UrlMapping>();

    List<UrlMapping> getUrlMappings() {
        return urlMappings;
    }

    void addMapping(UrlMapping urlMapping) {
        this.urlMappings.add(urlMapping);
    }

    void addMapping(int index, UrlMapping urlMapping) {
        this.urlMappings.add(index, urlMapping);
    }

    public C antMatchers(HttpMethod method, String... antPatterns) {
        return chainRequestMatchers(RequestMatchers.antMatchers(method, antPatterns));
    }

    public C antMatchers(String... antPatterns) {
        return chainRequestMatchers(RequestMatchers.antMatchers(antPatterns));
    }

    public C regexMatchers(HttpMethod method, String... regexPatterns) {
        return chainRequestMatchers(RequestMatchers.regexMatchers(method,
                regexPatterns));
    }

    public C regexMatchers(String... regexPatterns) {
        return chainRequestMatchers(RequestMatchers.regexMatchers(regexPatterns));
    }

    public C requestMatchers(RequestMatcher... requestMatchers) {
        return chainRequestMatchers(Arrays.asList(requestMatchers));
    }

    abstract C chainRequestMatchers(List<RequestMatcher> requestMatchers);

    LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> createRequestMap() {
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
        for (UrlMapping mapping : getUrlMappings()) {
            requestMap.put(mapping.getRequestMatcher(),
                    mapping.getConfigAttrs());
        }
        return requestMap;
    }

    static class UrlMapping {
        private RequestMatcher requestMatcher;
        private Collection<ConfigAttribute> configAttrs;

        public UrlMapping(RequestMatcher requestMatcher,
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
