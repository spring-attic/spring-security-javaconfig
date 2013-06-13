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
package org.springframework.security.config.annotation.web

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfiguratorAdapter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.test.util.ReflectionTestUtils;

import spock.lang.Specification

/**
 * @author Rob Winch
 *
 */
class AbstractConfiguredBuilderTests extends Specification {

    ConcreteAbstractConfiguredBuilder builder = new ConcreteAbstractConfiguredBuilder()

    def "Duplicate configurator is removed"() {
        when:
            builder.apply(new ConcreteConfigurator())
            builder.apply(new ConcreteConfigurator())
        then:
            ReflectionTestUtils.getField(builder,"configurators").size() == 1
    }

    private static class ConcreteAbstractConfiguredBuilder extends AbstractConfiguredSecurityBuilder<Object, ConcreteAbstractConfiguredBuilder> {
        public Object performBuild() throws Exception {
            return "success";
        }
    }

    private static class ConcreteConfigurator extends SecurityConfiguratorAdapter<Object, ConcreteAbstractConfiguredBuilder> { }
}
