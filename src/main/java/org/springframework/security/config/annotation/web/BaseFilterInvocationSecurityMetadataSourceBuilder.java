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

import java.util.List;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.ConsensusBased;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;

/**
 * @author Rob Winch
 *
 */
abstract class BaseFilterInvocationSecurityMetadataSourceBuilder<T> extends BaseRequestMatcherRegistry<T> implements SecurityBuilder<FilterInvocationSecurityMetadataSource> {


    final AccessDecisionManager createDefaultAccessDecisionManager() {
        return new ConsensusBased(decisionVoters());
    }

    public abstract FilterInvocationSecurityMetadataSource build();

    /**
     * @return
     */
    abstract List<AccessDecisionVoter> decisionVoters();
}