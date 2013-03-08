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
package org.springframework.security.config.annotation.web.util;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.RegexRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

/**
 * @author Rob Winch
 *
 */
public class RequestMatchers {


    public static List<RequestMatcher> antMatchers(HttpMethod httpMethod, String...antPatterns) {
        String method = httpMethod == null ? null : httpMethod.toString();
        List<RequestMatcher> matchers = new ArrayList<RequestMatcher>();
        for(String pattern : antPatterns) {
            matchers.add(new AntPathRequestMatcher(pattern, method));
        }
        return matchers;
    }

    public static List<RequestMatcher> antMatchers(String...antPatterns) {
        return antMatchers(null, antPatterns);
    }

    public static List<RequestMatcher> regexMatchers(HttpMethod httpMethod, String...regexPatterns) {
        String method = httpMethod == null ? null : httpMethod.toString();
        List<RequestMatcher> matchers = new ArrayList<RequestMatcher>();
        for(String pattern : regexPatterns) {
            matchers.add(new RegexRequestMatcher(pattern, method));
        }
        return matchers;
    }

    public static List<RequestMatcher> regexMatchers(String...regexPatterns) {
        return antMatchers(null, regexPatterns);
    }
}
