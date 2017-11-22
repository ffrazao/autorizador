package com.example.autenticador.seguranca;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.encoding.LdapShaPasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CompositeFilter;

@EnableOAuth2Client
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	/**
	 * utilizar este metodo para gerar senha para o usuario
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		for (int i = 0; i < 10; i++) {
			System.out.println(passwordEncoder.encode("123456"));
		}
	}

	@Autowired
	private DataSource dataSource;

	@Autowired
	private OAuth2ClientContext oauth2ClientContext;
	
	@Autowired
	private ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider;

	@Bean
	public ActiveDirectoryLdapAuthenticationProvider getActiveDirectoryLdapAuthenticationProvider() {
		ActiveDirectoryLdapAuthenticationProvider provider = new ActiveDirectoryLdapAuthenticationProvider("dftrans.df.gov.br", "ldap://10.64.0.100:389", "dc=dftrans,dc=gdfnet,dc=df");
		provider.setSearchFilter("(&(objectClass=user)(userPrincipalName={0}))");
		provider.setConvertSubErrorCodesToExceptions(true);

		return provider;
	}


	@Autowired
	public void configAuthentication(AuthenticationManagerBuilder auth) throws Exception {
		// @formatter:off
		auth
			.jdbcAuthentication().dataSource(dataSource).passwordEncoder(new BCryptPasswordEncoder())
				.usersByUsernameQuery("select username, password, enabled from users where username=?")
				.authoritiesByUsernameQuery("select username, role from user_roles where username=?").and()
			.authenticationProvider(activeDirectoryLdapAuthenticationProvider)
			.ldapAuthentication()
				.userDnPatterns("uid={0},ou=people")
				.groupSearchBase("ou=groups")
				.contextSource()
				.url("ldap://localhost:8389/dc=springframework,dc=org").and()
					.passwordCompare()
					.passwordEncoder(new LdapShaPasswordEncoder())
					.passwordAttribute("userPassword").and().and()
			.inMemoryAuthentication().withUser("a").password("a").roles("USER");
		// @formatter:on
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/login/**", "/h2**", "/h2/**", "/webjars/**")
				.permitAll().anyRequest().authenticated().and()
			.exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")).and()
			.formLogin().loginPage("/login").failureUrl("/login?error").usernameParameter("username").passwordParameter("password").and()
			.logout().logoutSuccessUrl("/").permitAll().and()
				//.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
			.csrf().disable()
			.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
		// @formatter:on
	}

	@Bean
	@ConfigurationProperties("facebook")
	public ClientResources facebook() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("github")
	public ClientResources github() {
		return new ClientResources();
	}

	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	private Filter ssoFilter() {
		CompositeFilter filter = new CompositeFilter();
		List<Filter> filters = new ArrayList<>();
		filters.add(ssoFilter(facebook(), "/login/facebook"));
		filters.add(ssoFilter(github(), "/login/github"));
		filter.setFilters(filters);
		return filter;
	}

	private Filter ssoFilter(ClientResources client, String path) {
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
		OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
		filter.setRestTemplate(template);
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(client.getResource().getUserInfoUri(), client.getClient().getClientId());
		tokenServices.setRestTemplate(template);
		filter.setTokenServices(tokenServices);
		return filter;
	}

}
