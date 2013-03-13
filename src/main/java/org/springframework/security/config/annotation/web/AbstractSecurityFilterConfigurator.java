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

import org.springframework.security.config.annotation.SecurityConfigurator;

/**
 * @author Rob Winch
 *
 */
abstract class AbstractSecurityFilterConfigurator implements SecurityConfigurator<SecurityFilterChainSecurityBuilder> {
    private SecurityFilterChainSecurityBuilder securityFilterChain;

    private boolean disabled;

    public SecurityFilterChainSecurityBuilder disable() {
        this.disabled = true;
        return securityFilterChain;
    }

    public final void init(SecurityFilterChainSecurityBuilder builder)
            throws Exception {
        if(disabled) {
            return;
        }
        doInit(builder);
    }

    void doInit(SecurityFilterChainSecurityBuilder builder) throws Exception {}

    public final void configure(SecurityFilterChainSecurityBuilder builder)
            throws Exception {
        if(disabled) {
            return;
        }
        doConfigure(builder);
    }

    void doConfigure(SecurityFilterChainSecurityBuilder builder) throws Exception {}

    public SecurityFilterChainSecurityBuilder and() throws Exception {
        if(securityFilterChain == null) {
            throw new IllegalStateException(SecurityFilterChainSecurityBuilder.class.getSimpleName() + " cannot be null");
        }
        return securityFilterChain;
    }

    public void setBuilder(
            SecurityFilterChainSecurityBuilder securityFilterChain) {
        this.securityFilterChain = securityFilterChain;
    }
}
