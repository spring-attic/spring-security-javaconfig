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

import org.springframework.context.ConfigurableApplicationContext
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.FilterChainProxy

import spock.lang.AutoCleanup
import spock.lang.Specification

/**
 *
 * @author Rob Winch
 */
abstract class BaseSpringSpec extends Specification {
    @AutoCleanup
    ConfigurableApplicationContext context

    def cleanup() {
        SecurityContextHolder.clearContext()
    }

    def loadConfig(Class<?>... configs) {
        context = new AnnotationConfigApplicationContext(configs)
        context
    }

    def findFilter(Class<?> filter, int index = 0) {
        filterChain(index).filters.find { filter.isAssignableFrom(it.class)}
    }

    def filterChain(int index=0) {
        filterChains()[index]
    }

    def filterChains() {
        context.getBean(FilterChainProxy).filterChains
    }

    AuthenticationManager authenticationManager() {
        context.getBean(AuthenticationManager)
    }
}
