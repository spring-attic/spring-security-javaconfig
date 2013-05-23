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
package org.springframework.security.web.util;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.RegexRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

/**
 * Utilities for creating {@link RequestMatcher} instances.
 *
 * @author Rob Winch
 * @since 3.1
 */
public class RequestMatchers {

    /**
     * Create a {@link List} of {@link AntPathRequestMatcher} instances.
     *
     * @param httpMethod the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
     * @param antPatterns the ant patterns to create {@link AntPathRequestMatcher} from
     *
     * @return a {@link List} of {@link AntPathRequestMatcher} instances
     */
    public static List<RequestMatcher> antMatchers(HttpMethod httpMethod, String...antPatterns) {
        String method = httpMethod == null ? null : httpMethod.toString();
        List<RequestMatcher> matchers = new ArrayList<RequestMatcher>();
        for(String pattern : antPatterns) {
            matchers.add(new AntPathRequestMatcher(pattern, method));
        }
        return matchers;
    }

    /**
     * Create a {@link List} of {@link AntPathRequestMatcher} instances that do not specify an {@link HttpMethod}.
     *
     * @param antPatterns the ant patterns to create {@link AntPathRequestMatcher} from
     *
     * @return a {@link List} of {@link AntPathRequestMatcher} instances
     */
    public static List<RequestMatcher> antMatchers(String...antPatterns) {
        return antMatchers(null, antPatterns);
    }

    /**
     * Create a {@link List} of {@link RegexRequestMatcher} instances.
     *
     * @param httpMethod the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
     * @param regexPatterns the regular expressions to create {@link RegexRequestMatcher} from
     *
     * @return a {@link List} of {@link RegexRequestMatcher} instances
     */
    public static List<RequestMatcher> regexMatchers(HttpMethod httpMethod, String...regexPatterns) {
        String method = httpMethod == null ? null : httpMethod.toString();
        List<RequestMatcher> matchers = new ArrayList<RequestMatcher>();
        for(String pattern : regexPatterns) {
            matchers.add(new RegexRequestMatcher(pattern, method));
        }
        return matchers;
    }

    /**
     * Create a {@link List} of {@link RegexRequestMatcher} instances that do not specify an {@link HttpMethod}.
     *
     *  @param regexPatterns the regular expressions to create {@link RegexRequestMatcher} from
     *
     * @return a {@link List} of {@link RegexRequestMatcher} instances
     */
    public static List<RequestMatcher> regexMatchers(String...regexPatterns) {
        return regexMatchers(null, regexPatterns);
    }

    private RequestMatchers() {}
}
