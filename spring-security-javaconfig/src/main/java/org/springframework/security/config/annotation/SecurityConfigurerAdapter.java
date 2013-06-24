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



/**
 * A base class for {@link SecurityConfigurer} that allows subclasses to only
 * implement the methods they are interested in. It also provides a mechanism
 * for using the {@link SecurityConfigurer} and when done gaining access to the
 * {@link SecurityBuilder} that is being configured.
 *
 * @author Rob Winch
 *
 * @param <O>
 *            The Object being built by B
 * @param <B>
 *            The Builder that is building O and is configured by {@link SecurityConfigurerAdapter}
 */
public abstract class SecurityConfigurerAdapter<O,B extends SecurityBuilder<O>> implements SecurityConfigurer<O,B> {
    private B securityBuilder;

    private ObjectPostProcessor objectPostProcessor = ObjectPostProcessor.QUIESCENT_POSTPROCESSOR;

    @Override
    public void init(B builder) throws Exception {}

    @Override
    public void configure(B builder) throws Exception {}

    /**
     * Return the {@link SecurityBuilder} when done using the
     * {@link SecurityConfigurer}. This is useful for method chaining.
     *
     * @return
     */
    public B and() {
        return getBuilder();
    }

    /**
     * Gets the {@link SecurityBuilder}. Cannot be null.
     *
     * @return the {@link SecurityBuilder}
     * @throw {@link IllegalStateException} if {@link SecurityBuilder} is null
     */
    protected final B getBuilder() {
        if(securityBuilder == null) {
            throw new IllegalStateException("securityBuilder cannot be null");
        }
        return securityBuilder;
    }

    /**
     * Performs post processing of an object. The default is to delegate to the
     * {@link ObjectPostProcessor}.
     *
     * @param object the Object to post process
     * @return the possibly modified Object to use
     */
    protected <T> T postProcess(T object) {
        return this.objectPostProcessor.postProcess(object);
    }

    /**
     * Sets the {@link ObjectPostProcessor} to be used for this
     * {@link SecurityConfigurerAdapter}. The default implementation does
     * nothing to the object.
     *
     * @param objectPostProcessor the {@link ObjectPostProcessor} to use
     */
    public void setObjectPostProcessor(ObjectPostProcessor objectPostProcessor) {
        this.objectPostProcessor = objectPostProcessor;
    }

    public void setBuilder(
            B securityFilterChain) {
        this.securityBuilder = securityFilterChain;
    }
}
