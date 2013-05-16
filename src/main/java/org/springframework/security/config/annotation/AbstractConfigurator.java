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
package org.springframework.security.config.annotation;

import org.springframework.security.config.annotation.web.HttpConfigurator;


/**
 *
 * @author Rob Winch
 *
 * @param <O> The Object being built by B
 * @param <B> The Builder that is building O
 */
public abstract class AbstractConfigurator<O,B extends SecurityBuilder<O>> implements SecurityConfigurator<O,B> {
    private B securityBuilder;

    private boolean disabled;

    public B disable() {
        this.disabled = true;
        return securityBuilder;
    }

    @Override
    public final void init(B builder)
            throws Exception {
        if(disabled) {
            return;
        }
        doInit(builder);
    }

    protected void doInit(B builder) throws Exception {}

    @Override
    public final void configure(B builder)
            throws Exception {
        if(disabled) {
            return;
        }
        doConfigure(builder);
    }

    protected void doConfigure(B builder) throws Exception {}

    public B and() throws Exception {
        if(securityBuilder == null) {
            throw new IllegalStateException(HttpConfigurator.class.getSimpleName() + " cannot be null");
        }
        return securityBuilder;
    }

    public void setBuilder(
            B securityFilterChain) {
        this.securityBuilder = securityFilterChain;
    }
}
