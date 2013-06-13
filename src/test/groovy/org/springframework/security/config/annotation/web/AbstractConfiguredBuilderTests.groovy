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
import org.springframework.security.config.annotation.SecurityConfigurator
import org.springframework.security.config.annotation.SecurityConfiguratorAdapter
import org.springframework.test.util.ReflectionTestUtils

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


    def "Configurator.init can apply another configurator"() {
        setup:
            DelegateConfigurator.CONF = Mock(SecurityConfiguratorAdapter)
        when:
            builder.apply(new DelegateConfigurator())
            builder.build()
        then:
            1 * DelegateConfigurator.CONF.init(builder)
            1 * DelegateConfigurator.CONF.configure(builder)
    }

    private static class DelegateConfigurator extends SecurityConfiguratorAdapter<Object, ConcreteAbstractConfiguredBuilder> {
        private static SecurityConfigurator<Object, ConcreteAbstractConfiguredBuilder> CONF;

        @Override
        public void init(ConcreteAbstractConfiguredBuilder builder)
                throws Exception {
            builder.apply(CONF);
        }
    }

    private static class ConcreteConfigurator extends SecurityConfiguratorAdapter<Object, ConcreteAbstractConfiguredBuilder> { }

    private static class ConcreteAbstractConfiguredBuilder extends AbstractConfiguredSecurityBuilder<Object, ConcreteAbstractConfiguredBuilder> {
        public Object performBuild() throws Exception {
            return "success";
        }
    }

}
