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
import org.springframework.security.config.annotation.SecurityConfiguratorAdapter;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * Adds a convenient base class for {@link SecurityConfigurator} instances that
 * operate on {@link HttpConfiguration}.
 *
 * @author Rob Winch
 *
 */
abstract class BaseHttpConfigurator extends SecurityConfiguratorAdapter<DefaultSecurityFilterChain,HttpConfiguration> {

    /**
     * Convenience method to invoke
     * {@link LifecycleManager#registerLifecycle(Object)}
     *
     * @param object
     *            the Object to register
     * @return the potentially modified version of the Object
     */
    final <T> T registerLifecycle(T object) {
        getBuilder().registerLifecycle(object);
        return object;
    }
}
