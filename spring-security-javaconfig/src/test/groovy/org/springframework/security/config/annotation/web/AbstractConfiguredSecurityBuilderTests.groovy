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

import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder
import org.springframework.security.config.annotation.SecurityConfigurer
import org.springframework.security.config.annotation.SecurityConfigurerAdapter
import org.springframework.test.util.ReflectionTestUtils

import spock.lang.Specification

/**
 * @author Rob Winch
 *
 */
class AbstractConfiguredSecurityBuilderTests extends Specification {

    ConcreteAbstractConfiguredBuilder builder = new ConcreteAbstractConfiguredBuilder()

    def "Duplicate configurer is removed"() {
        when:
            builder.apply(new ConcreteConfigurer())
            builder.apply(new ConcreteConfigurer())
        then:
            ReflectionTestUtils.getField(builder,"configurers").size() == 1
    }

    def "build twice fails"() {
        setup:
            builder.build()
        when:
            builder.build()
        then:
            thrown(IllegalStateException)
    }

    def "getObject before build fails"() {
        when:
            builder.getObject()
        then:
            thrown(IllegalStateException)
    }

    def "Configurer.init can apply another configurer"() {
        setup:
            DelegateConfigurer.CONF = Mock(SecurityConfigurerAdapter)
        when:
            builder.apply(new DelegateConfigurer())
            builder.build()
        then:
            1 * DelegateConfigurer.CONF.init(builder)
            1 * DelegateConfigurer.CONF.configure(builder)
    }

    private static class DelegateConfigurer extends SecurityConfigurerAdapter<Object, ConcreteAbstractConfiguredBuilder> {
        private static SecurityConfigurer<Object, ConcreteAbstractConfiguredBuilder> CONF;

        @Override
        public void init(ConcreteAbstractConfiguredBuilder builder)
                throws Exception {
            builder.apply(CONF);
        }
    }

    private static class ConcreteConfigurer extends SecurityConfigurerAdapter<Object, ConcreteAbstractConfiguredBuilder> { }

    private static class ConcreteAbstractConfiguredBuilder extends AbstractConfiguredSecurityBuilder<Object, ConcreteAbstractConfiguredBuilder> {
        public Object performBuild() throws Exception {
            return "success";
        }
    }

}
