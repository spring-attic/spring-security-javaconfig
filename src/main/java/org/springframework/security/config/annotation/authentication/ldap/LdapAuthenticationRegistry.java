package org.springframework.security.config.annotation.authentication.ldap;

import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;

public interface LdapAuthenticationRegistry {

	LdapAuthenticationRegistry userDnPatterns(
			String... userDnPatterns);

	LdapAuthenticationRegistry userDetailsContextMapper(
			UserDetailsContextMapper userDetailsContextMapper);

	LdapAuthenticationRegistry groupRoleAttribute(
			String groupRoleAttribute);

	LdapAuthenticationRegistry groupSearchBase(
			String groupSearchBase);

	LdapAuthenticationRegistry groupSearchFilter(
			String groupSearchFilter);

	LdapAuthenticationRegistry rolePrefix(
			String rolePrefix);

	LdapAuthenticationRegistry userSearchFilter(
			String userSearchFilter);

}