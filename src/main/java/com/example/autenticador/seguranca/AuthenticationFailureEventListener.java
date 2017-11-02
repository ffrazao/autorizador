package com.example.autenticador.seguranca;

import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationFailureEventListener implements ApplicationListener<AuthenticationFailureBadCredentialsEvent> {

	public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent e) {
		Authentication auth = e.getAuthentication();

		System.out.printf("falhou %s\n", auth.getName());
	}
}