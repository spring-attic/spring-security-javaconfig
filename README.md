Spring Security Java Config
======================

A project for Spring Security Java Configuration Support. We plan to release this jar in a number of milestones
to be able to iterate quickly. Additionally, this will allow users of Spring Security 3.1.x to use the
Java Configuration earlier and give more feedback. Eventually (targeting spring-security-config-3.2.0.RELEASE)
we will merge this code in with spring-security-config.

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
Before contributing or logging an issue please be sure to the issue does not already exist in this project's [issue tracking](https://github.com/SpringSource/spring-security-javaconfig/issues). If one does not exist, please create an issue.

If you see anything you'd like to change we encourage taking advantage of github's social coding features by making the change in a [fork of this repository](http://help.github.com/forking/) and sending a pull request.

Before we accept a non-trivial patch or pull request we will need you to sign the [contributor's agreement](https://support.springsource.com/spring_committer_signup). Signing the contributor's agreement does not grant anyone commit rights to the main repository, but it does mean that we can accept your contributions, and you will get an author credit if we do. Active contributors might be asked to join the core team, and given the ability to merge pull requests.

License
==============
The Spring Security Java Config project is available under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).

