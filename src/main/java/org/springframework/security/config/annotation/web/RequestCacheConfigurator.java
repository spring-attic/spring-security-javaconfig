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

import org.springframework.security.config.annotation.SecurityConfiguratorAdapter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;

/**
 * @author Rob Winch
 *
 */
public class RequestCacheConfigurator extends SecurityConfiguratorAdapter<DefaultSecurityFilterChain,HttpConfiguration> {
    private RequestCache requestCache;

    @Override
    public void configure(HttpConfiguration http) throws Exception {
        RequestCacheAwareFilter requestCacheFilter = new RequestCacheAwareFilter(getRequestCache(http));
        http.addFilter(requestCacheFilter);
    }

    /**
     * Gets the {@link RequestCache} to use. If one is defined using
     * {@link #requestCache(org.springframework.security.web.savedrequest.RequestCache)}, then it is used. Otherwise, an
     * attempt to find a {@link RequestCache} shared object is made. If that fails, an {@link HttpSessionRequestCache}
     * is used
     *
     * @param http the {@link HttpConfiguration} to attempt to fined the shared object
     * @return the {@link RequestCache} to use
     */
    private RequestCache getRequestCache(HttpConfiguration http) {
        if(this.requestCache != null) {
            return this.requestCache;
        }
        RequestCache result = http.getSharedObject(RequestCache.class);
        if(result != null) {
            return result;
        }
        return new HttpSessionRequestCache();
    }
}