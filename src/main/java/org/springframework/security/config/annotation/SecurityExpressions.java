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
package org.springframework.security.config.annotation;

import org.apache.commons.lang.StringUtils;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class SecurityExpressions {
    public static final String permitAll = "permitAll";
    public static final String authenticated = "authenticated";
    public static final String fullyAuthenticated = "fullyAuthenticated";

    public static String hasRole(String role) {
        return "hasRole('ROLE_" + role + "')";
    }

    public static String hasAuthority(String authority) {
        return "hasAuthority('" + authority + "')";
    }

    public static String hasAnyAuthority(String... authorities) {
        String anyAuthorities = StringUtils.join(authorities, "','");
        return "hasAnyAuthority('" + anyAuthorities + "')";
    }
}
