import { Config, Env, Nested } from '../decorators';

@Config
class SamlConfig {
	/** Whether SAML-based single sign-on is enabled. */
	@Env('N8N_SSO_SAML_LOGIN_ENABLED')
	loginEnabled: boolean = false;

	/** Label shown on the login button for SAML (for example, "Sign in with SAML"). */
	@Env('N8N_SSO_SAML_LOGIN_LABEL')
	loginLabel: string = '';
}

@Config
class OidcConfig {
	/** Whether OIDC-based single sign-on is enabled. */
	@Env('N8N_SSO_OIDC_LOGIN_ENABLED')
	loginEnabled: boolean = false;

	/** OIDC issuer URL (also used as discovery endpoint). */
	@Env('N8N_SSO_OIDC_ISSUER_URL')
	issuerUrl: string = '';

	/** OIDC client ID. */
	@Env('N8N_SSO_OIDC_CLIENT_ID')
	clientId: string = '';

	/** OIDC client secret. */
	@Env('N8N_SSO_OIDC_CLIENT_SECRET')
	clientSecret: string = '';

	/** OIDC redirect URI (defaults to /login/oidc/callback if empty). */
	@Env('N8N_SSO_OIDC_REDIRECT_URI')
	redirectUri: string = '';

	/** Name of the OIDC claim to use for role mapping. */
	@Env('N8N_SSO_OIDC_ROLE_CLAIM')
	roleClaim: string = 'role';

	/** Value of the role claim that indicates an admin user. */
	@Env('N8N_SSO_OIDC_ADMIN_ROLE')
	adminRole: string = 'admin';

	/** Whether to automatically create user accounts on first OIDC login. */
	@Env('N8N_SSO_OIDC_AUTO_PROVISION')
	autoProvision: boolean = true;
}

@Config
class LdapConfig {
	/** Whether LDAP-based single sign-on is enabled. */
	@Env('N8N_SSO_LDAP_LOGIN_ENABLED')
	loginEnabled: boolean = false;

	/** Label shown on the login button for LDAP (for example, "Sign in with LDAP"). */
	@Env('N8N_SSO_LDAP_LOGIN_LABEL')
	loginLabel: string = '';
}

@Config
class ProvisioningConfig {
	/** Whether to set the user's instance role from an SSO claim during login. */
	@Env('N8N_SSO_SCOPES_PROVISION_INSTANCE_ROLE')
	scopesProvisionInstanceRole: boolean = false;

	/** Whether to set project–role mappings from an SSO claim during login. */
	@Env('N8N_SSO_SCOPES_PROVISION_PROJECT_ROLES')
	scopesProvisionProjectRoles: boolean = false;

	/** Name of the OAuth scope to request for SSO provisioning. */
	@Env('N8N_SSO_SCOPES_NAME')
	scopesName: string = 'n8n';

	/** Name of the SSO claim that contains the user's instance role (for provisioning). */
	@Env('N8N_SSO_SCOPES_INSTANCE_ROLE_CLAIM_NAME')
	scopesInstanceRoleClaimName: string = 'n8n_instance_role';

	/** Name of the SSO claim that contains project–role mappings (for provisioning). */
	@Env('N8N_SSO_SCOPES_PROJECTS_ROLES_CLAIM_NAME')
	scopesProjectsRolesClaimName: string = 'n8n_projects';

	/** Whether to use expression-based role mapping rules instead of direct SSO claim provisioning. */
	@Env('N8N_SSO_SCOPES_USE_EXPRESSION_MAPPING')
	scopesUseExpressionMapping: boolean = false;
}

@Config
export class SsoConfig {
	/** Whether to automatically create user accounts when someone signs in via SSO for the first time. */
	@Env('N8N_SSO_JUST_IN_TIME_PROVISIONING')
	justInTimeProvisioning: boolean = true;

	/** Whether the login screen redirects directly to SSO instead of showing email/password. */
	@Env('N8N_SSO_REDIRECT_LOGIN_TO_SSO')
	redirectLoginToSso: boolean = true;

	@Nested
	saml: SamlConfig;

	@Nested
	oidc: OidcConfig;

	@Nested
	ldap: LdapConfig;

	@Nested
	provisioning: ProvisioningConfig;
}
