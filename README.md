Spring Security Java Config
======================

A project for Spring Security Java Configuration Support. This project is currently released as a stand alone project that is compatible with Spring Security 3.1.x and Spring 3.2.3 to allow users to try it out
before the Spring Security 3.2.x release. The code is also migrated into Spring Security 3.2.0.M2+ and will be maintained there. There are no plans to make another release of the stand alone module. Instead users
will be encouraged to update to Spring Security 3.2 when it is made final.

Getting Started
======================

* [Quick Start - Hello Security](quickstart.md)
* [Web Security Samples](samples-web.md)
* [Method Security Samples](samples-method.md)
* Complete web applications samples - We include a number of complete [Sample Web Applications](./samples/) that use Spring Security Java Configuration.
* XML Namespace to Java Config - Refer to the tests for further examples. You will notice a convention of Namespace<Security Element>Tests where <Security Element> is the Security Namespace
Element. For example, to learn how the <http> element and its attributes map to Spring Security Java Configuration look in the NamespaceHttpTests

FAQ
==============

Q: I'm getting getting a NoSuchBeanDefinitionException:

The full Exception is something similar (bean names can vary)

```
Caused by: org.springframework.beans.factory.NoSuchBeanDefinitionException: No bean named 'org.springframework.security.userDetailsService' is defined
    at org.springframework.beans.factory.support.DefaultListableBeanFactory.getBeanDefinition(DefaultListableBeanFactory.java:568)
    at org.springframework.beans.factory.support.AbstractBeanFactory.getMergedLocalBeanDefinition(AbstractBeanFactory.java:1099)
    at org.springframework.beans.factory.support.AbstractBeanFactory.doGetBean(AbstractBeanFactory.java:278)
    at org.springframework.beans.factory.support.AbstractBeanFactory.getBean(AbstractBeanFactory.java:194)
    at org.springframework.context.annotation.ConfigurationClassEnhancer$BeanMethodInterceptor.intercept(ConfigurationClassEnhancer.java:297)
    at org.test.demo.SecurityConfiguration$ApiConfiguration$$EnhancerByCGLIB$$e681011a.userDetailsServiceBean(<generated>)
    at org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapter.http(WebSecurityConfigurerAdapter.java:66)
```

A: If you are get the error above or something similar, you should ensure you have updated to Spring Framework 3.2.3.RELEASE+ or 4.0.0.M1+ to avoid running into [SPR-10546](https://jira.springsource.org/browse/SPR-10546)

Contributing
==============

The code has been migrated and merged into Spring Security's 3.2.0.M2+ codebase and will be maintained there from now on. Please see [Spring Security's Contributing Guidelines](https://github.com/SpringSource/spring-security/blob/master/CONTRIBUTING.md) for details on how to contribute.


License
==============
The Spring Security Java Config project is available under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).

