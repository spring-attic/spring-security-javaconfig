Spring Security Java Config
======================

A project for Spring Security Java Configuration Support. This project is going to be merged into Spring Security 3.2, but to allow users to try it before 3.2 final release we will release
each milestone as a distinct jar too.

Getting Started
======================

Below are the steps to get started quickly.

Update Dependencies
----------------------

To get started update your dependencies to include the Spring Security Java Config jar. If you are using Maven, you will want to ensure that you have included the Spring Snapshot repository:

    <repositories>
        ...

        <repository>
            <id>spring-snapshot</id>
            <url>http://repo.springsource.org/libs-snapshot</url>
        </repository>
    </repositories>

You will then need to include the Spring Security Java Configuration jar.

    <dependencies>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-javaconfig</artifactId>
            <version>1.0.0.CI-SNAPSHOT</version>
    </dependencies>

Basic Configuration
----------------------


import static org.springframework.security.config.annotation.SecurityExpressions.*;
import static org.springframework.security.config.annotation.authentication.AuthenticationSecurityBuilders.*;
import static org.springframework.security.config.annotation.web.FilterInvocationSecurityMetadataSourceSecurityBuilder.*;
import static org.springframework.security.config.annotation.web.WebSecurityConfigurators.*;


    @Configuration
    public static class SampleSimpleWebSecurityConfig extends SimpleWebSecurityConfig {
        protected FilterChainProxySecurityBuilder configure(
                FilterChainProxySecurityBuilder securityFilterChains) {
            return securityFilterChains
                // spring security ignores these URLs
                .ignoring(antMatchers("/resources/**"))
        }

        protected FilterInvocationSecurityMetadataSourceSecurityBuilder filterInvocationBuilder() {
            return interceptUrls()
                .interceptUrl(antMatchers("/signup","/about"), permitAll)
                .interceptUrl(antMatchers("/**"), hasRole("ROLE_USER"));
        }

        protected SecurityFilterChainSecurityBuilder configure(
                SecurityFilterChainSecurityBuilder springSecurityFilterChain) {
            return springSecurityFilterChain
                .apply(formLogin()
                    // ensure the URLs for login are publicly accessible
                    .permitAll());
        }

        protected AuthenticationManager authenticationMgr() throws Exception {
            return inMemoryAuthentication(
                user("user").password("password").roles("USER"),
                user("admin").password("password").roles("USER", "ADMIN")
            ).authenticationManager();
        }
    }
