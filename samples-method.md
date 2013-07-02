Method Security Samples
======================

Below are a few additional samples to get you up and running quickly

Sample Global Security Configuration
-------------

See [SampleEnableGlobalMethodSecurityTests.groovy](src/test/groovy/org/springframework/security/config/annotation/method/SampleEnableGlobalMethodSecurityTests.groovy)

Global configuration is quite simple. For example, the following Java Configuration:

```java
    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled=true)
    public class SampleWebSecurityConfig {
        @Bean
        public MethodSecurityService methodSecurityService() {
            return new MethodSecurityServiceImpl()
        }

        @Bean
        public AuthenticationManager authenticationManager() throws Exception {
            return new AuthenticationManagerBuilder()
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN").and()
                .build();
        }
    }
```

is the equivalent of:

```xml
    <global-method-security pre-post-annotations="enabled"/>
    <authentication-manager>
      <authentication-provider>
        <user-service>
          <user name="user" password="password" authorities="ROLE_USER"/>
          <user name="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
        </user-service>
      </authentication-provider>
    </authentication-manager>
    <beans:bean id="methodSecuriytService" class="MethodSecurityServiceImpl"/>
```

There are additional attributes on `EnableGlobalMethodSecurity`, but in more advanced situations you may want to refer to another object. In order to do this,
override the `GlobalMethodSecurityConfiguration` class. For example, following Java configuration demonstrates how to override the MethodExpressionHandler to use
`CustomPermissionEvaluator`.

```java
    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled=true)
    public class CustomPermissionEvaluatorWebSecurityConfig extends GlobalMethodSecurityConfiguration {
        @Bean
        public MethodSecurityService methodSecurityService() {
            return new MethodSecurityServiceImpl()
        }

        @Override
        protected MethodSecurityExpressionHandler expressionHandler() {
            DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
            expressionHandler.setPermissionEvaluator(new CustomPermissionEvaluator());
            return expressionHandler;
        }

        @Override
        protected void registerAuthentication(AuthenticationManagerBuilder auth)
            throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN");
        }
    }
```

The configuration above is the similar to the following XML configuration:

```xml
    <global-method-security pre-post-annotations="enabled">
        <expression-handler ref="expressionHandler"/>
    </global-method-security>
    <authentication-manager>
      <authentication-provider>
        <user-service>
          <user name="user" password="password" authorities="ROLE_USER"/>
          <user name="admin" password="password" authorities="ROLE_USER,ROLE_ADMIN"/>
        </user-service>
      </authentication-provider>
    </authentication-manager>
    <beans:bean id="methodSecuriytService" class="MethodSecurityServiceImpl"/>
    <beans:bean id="expressionHandler" class="CustomExpressionHandler"/>
```
