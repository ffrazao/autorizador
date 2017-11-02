package com.example.autenticador.seguranca;

import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationSuccessEventListener implements ApplicationListener<AuthenticationSuccessEvent> {

	public void onApplicationEvent(AuthenticationSuccessEvent e) {
		Authentication auth = e.getAuthentication();

		System.out.printf("acertou %s\n", auth.getName());
	}
}