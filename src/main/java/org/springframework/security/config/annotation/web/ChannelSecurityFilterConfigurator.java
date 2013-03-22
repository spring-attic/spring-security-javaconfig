/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.config.annotation.web;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.channel.ChannelProcessor;
import org.springframework.security.web.access.channel.InsecureChannelProcessor;
import org.springframework.security.web.access.channel.SecureChannelProcessor;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.RequestMatcher;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class ChannelSecurityFilterConfigurator extends BaseRequestMatcherRegistry<ChannelSecurityFilterConfigurator.AuthorizedUrl> {
    private ChannelProcessingFilter channelFilter = new ChannelProcessingFilter();
    private LinkedHashMap<RequestMatcher,Collection<ConfigAttribute>> requestMap = new LinkedHashMap<RequestMatcher,Collection<ConfigAttribute>>();
    private InsecureChannelProcessor insecureChannelProcessor = new InsecureChannelProcessor();
    private SecureChannelProcessor secureChannelProcessor = new SecureChannelProcessor();

    protected void doConfigure(DefaultSecurityFilterChainBuilder builder)
            throws Exception {
        ChannelDecisionManagerImpl channelDecisionManager = new ChannelDecisionManagerImpl();
        channelDecisionManager.setChannelProcessors(Arrays.<ChannelProcessor>asList(insecureChannelProcessor,secureChannelProcessor));
        channelFilter.setChannelDecisionManager(channelDecisionManager);

        DefaultFilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource = new DefaultFilterInvocationSecurityMetadataSource(requestMap);
        channelFilter.setSecurityMetadataSource(filterInvocationSecurityMetadataSource);

        builder.addFilter(channelFilter);
    }


    private ChannelSecurityFilterConfigurator addAttribute(String attribute, List<RequestMatcher> matchers) {
        for(RequestMatcher matcher : matchers) {
            Collection<ConfigAttribute> attrs = Arrays.<ConfigAttribute>asList(new SecurityConfig(attribute));
            requestMap.put(matcher, attrs);
        }
        return this;
    }

    AuthorizedUrl chainRequestMatchers(List<RequestMatcher> requestMatchers) {
        return new AuthorizedUrl(requestMatchers);
    }

    public class AuthorizedUrl {
        private List<RequestMatcher> requestMatchers;

        private AuthorizedUrl(List<RequestMatcher> requestMatchers) {
            this.requestMatchers = requestMatchers;
        }

        public ChannelSecurityFilterConfigurator requiresSecure() {
            return addAttribute(secureChannelProcessor.getSecureKeyword(), requestMatchers);
        }

        public ChannelSecurityFilterConfigurator requiresInsecure() {
            return addAttribute(insecureChannelProcessor.getInsecureKeyword(), requestMatchers);
        }
    }
}