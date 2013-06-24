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

import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * Adds a convenient base class for {@link SecurityConfigurer} instances that
 * operate on {@link HttpConfiguration}.
 *
 * @author Rob Winch
 *
 */
abstract class BaseHttpConfigurer<B extends HttpBuilder<B>> extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, B> {

    /**
     * Convenience method to invoke
     * {@link ObjectPostProcessor#postProcess(Object)}
     *
     * @param object
     *            the Object to register
     * @return the potentially modified version of the Object
     */
    final <T> T postProcess(T object) {
        getBuilder().postProcess(object);
        return object;
    }
}
