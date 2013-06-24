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

import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.SecurityBuilderPostProcessor;
import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.channel.InsecureChannelProcessor
import org.springframework.security.web.access.channel.SecureChannelProcessor
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;

/**
 *
 * @author Rob Winch
 */
class RequestCacheConfigurerTests extends BaseSpringSpec {

    def "requestCache LifecycleManager"() {
        setup:
            SecurityBuilderPostProcessor lifecycleManager = Mock()
            HttpConfiguration http = new HttpConfiguration(lifecycleManager, authenticationBldr)
        when:
            http
                .requestCache()
                    .and()
                .build()

        then: "RequestCacheAwareFilter is registered with LifecycleManager"
            1 * lifecycleManager.postProcess(_ as RequestCacheAwareFilter) >> {RequestCacheAwareFilter o -> o}
    }
}
