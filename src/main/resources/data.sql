INSERT INTO oauth_client_details
	(client_id, client_secret, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity,
	refresh_token_validity, additional_information, autoapprove)
VALUES
	('fooClientIdPassword', 'secret', 'foo,read,write', 'password,authorization_code,refresh_token', null, null, 36000, 36000, null, true);

INSERT INTO oauth_client_details
	(client_id, client_secret, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity,
	refresh_token_validity, additional_information, autoapprove)
VALUES
	('sampleClientId', 'secret', 'read,write,foo,bar', 'implicit', null, null, 36000, 36000, null, false);
	
INSERT INTO oauth_client_details
	(client_id, client_secret, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity,
	refresh_token_validity, additional_information, autoapprove)
VALUES
	('barClientIdPassword', 'secret', 'bar,read,write', 'password,authorization_code,refresh_token', null, null, 36000, 36000, null, true);

	
INSERT INTO users(username,password,enabled) VALUES ('mkyong','$2a$10$uRJDR1QEKozYFbTXR/NW8O6KaifIn0KVQN03bVhHFkqIg5jAEF0na', true);
INSERT INTO users(username,password,enabled) VALUES ('alex','$2a$10$3M5WGlFic1OrUm8tHHlXz.b0MXLXX6V85VPILS8i.eX2INkhoT3Ze', true); -- usr:alex/pass:alex

INSERT INTO user_roles (username, role) VALUES ('mkyong', 'ROLE_USER');
INSERT INTO user_roles (username, role) VALUES ('mkyong', 'ROLE_ADMIN');
INSERT INTO user_roles (username, role) VALUES ('alex', 'ROLE_USER');