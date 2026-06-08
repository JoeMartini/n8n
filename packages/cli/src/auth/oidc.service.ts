import { Logger } from '@n8n/backend-common';
import { GlobalConfig, InstanceSettingsLoaderConfig } from '@n8n/config';
import {
	AuthIdentityRepository,
	GLOBAL_MEMBER_ROLE,
	GLOBAL_OWNER_ROLE,
	isValidEmail,
	User,
	UserRepository,
} from '@n8n/db';
import { Service } from '@n8n/di';
import type { Configuration } from 'openid-client';

import { UrlService } from '@/services/url.service';

@Service()
export class OidcService {
	private oidcConfiguration: Configuration | undefined;

	// eslint-disable-next-line @typescript-eslint/consistent-type-imports
	private openidClient: typeof import('openid-client');

	constructor(
		private readonly instanceSettingsLoaderConfig: InstanceSettingsLoaderConfig,
		private readonly urlService: UrlService,
		private readonly globalConfig: GlobalConfig,
		private readonly userRepository: UserRepository,
		private readonly authIdentityRepository: AuthIdentityRepository,
		private readonly logger: Logger,
	) {}

	async init(): Promise<void> {
		if (!this.instanceSettingsLoaderConfig.oidcLoginEnabled) {
			this.logger.debug('OIDC login is disabled.');
			return;
		}

		if (
			!this.instanceSettingsLoaderConfig.oidcDiscoveryEndpoint ||
			!this.instanceSettingsLoaderConfig.oidcClientId
		) {
			throw new Error(
				'OIDC is enabled but missing required configuration: discovery endpoint and client ID',
			);
		}

		this.openidClient = await import('openid-client');
		this.oidcConfiguration = await this.openidClient.discovery(
			new URL(this.instanceSettingsLoaderConfig.oidcDiscoveryEndpoint),
			this.instanceSettingsLoaderConfig.oidcClientId,
			this.instanceSettingsLoaderConfig.oidcClientSecret,
		);

		this.logger.debug('OIDC discovery completed');
	}

	getCallbackUrl(): string {
		return `${this.urlService.getInstanceBaseUrl()}/${this.globalConfig.endpoints.rest}/auth/oidc/callback`;
	}

	async buildAuthorizationUrl(): Promise<{ url: URL; state: string; nonce: string }> {
		const configuration = this.getConfiguration();

		const state = this.openidClient.randomState();
		const nonce = this.openidClient.randomNonce();

		const prompt = this.instanceSettingsLoaderConfig.oidcPrompt;
		const acrValues = this.instanceSettingsLoaderConfig.oidcAcrValues;
		const scope = 'openid email profile';

		const url = this.openidClient.buildAuthorizationUrl(configuration, {
			redirect_uri: this.getCallbackUrl(),
			response_type: 'code',
			scope,
			prompt,
			state,
			nonce,
			...(acrValues && { acr_values: acrValues }),
		});

		return { url, state, nonce };
	}

	async handleCallback(callbackUrl: URL, storedState: string, storedNonce: string): Promise<User> {
		const configuration = this.getConfiguration();

		if (!storedState) {
			this.logger.error('State parameter is missing');
			throw new Error('Missing state parameter');
		}

		let tokens;
		try {
			tokens = await this.openidClient.authorizationCodeGrant(configuration, callbackUrl, {
				expectedState: storedState,
				expectedNonce: storedNonce,
			});
		} catch (error) {
			this.logger.error('Failed to exchange authorization code for tokens', { error });
			throw new Error('Invalid authorization code');
		}

		let claims;
		try {
			claims = tokens.claims();
		} catch (error) {
			this.logger.error('Failed to extract claims from tokens', { error });
			throw new Error('Invalid token');
		}

		if (!claims) {
			throw new Error('No claims found in the OIDC token');
		}

		let userInfo;
		try {
			userInfo = await this.openidClient.fetchUserInfo(
				configuration,
				tokens.access_token,
				claims.sub,
			);
		} catch (error) {
			this.logger.error('Failed to fetch user info', { error });
			throw new Error('Failed to fetch user info');
		}

		if (!userInfo.email) {
			throw new Error('An email is required');
		}

		if (!isValidEmail(userInfo.email)) {
			throw new Error('Invalid email format');
		}

		return await this.resolveUser(claims, userInfo);
	}

	private getConfiguration(): Configuration {
		if (!this.oidcConfiguration) {
			throw new Error('OIDC client not initialized');
		}
		if (!this.openidClient) {
			void import('openid-client').then((mod) => {
				this.openidClient = mod;
			});
		}
		return this.oidcConfiguration;
	}

	private async resolveUser(
		claims: Record<string, unknown>,
		userInfo: Record<string, unknown>,
	): Promise<User> {
		const sub = String(claims.sub);
		const email = String(userInfo.email);
		const firstName = userInfo.given_name ? String(userInfo.given_name) : undefined;
		const lastName = userInfo.family_name ? String(userInfo.family_name) : undefined;

		// 1. Find existing user by OIDC identity
		const existingIdentity = await this.authIdentityRepository.findOne({
			where: { providerId: sub, providerType: 'oidc' },
			relations: { user: { role: true } },
		});

		if (existingIdentity) {
			return existingIdentity.user;
		}

		// 2. Find existing user by email and link OIDC identity
		const existingUser = await this.userRepository.findOne({
			where: { email },
			relations: ['authIdentities', 'role'],
		});

		if (existingUser) {
			this.logger.debug(
				`OIDC login: User with email ${email} already exists, linking OIDC identity.`,
			);
			const identity = this.authIdentityRepository.create({
				providerId: sub,
				providerType: 'oidc',
				userId: existingUser.id,
			});
			await this.authIdentityRepository.save(identity);
			return existingUser;
		}

		// 3. Auto-provision new user if enabled
		if (!this.globalConfig.sso.justInTimeProvisioning) {
			throw new Error('User not found and auto-provisioning is disabled');
		}

		const roles = this.extractRoles(claims);
		const isAdmin = this.isAdminRole(roles);
		const role = isAdmin ? GLOBAL_OWNER_ROLE : GLOBAL_MEMBER_ROLE;

		const { user: newUser } = await this.userRepository.createUserWithProject({
			firstName,
			lastName,
			email,
			authIdentities: [],
			role,
			password: 'no password set',
		});

		await this.authIdentityRepository.save(
			this.authIdentityRepository.create({
				providerId: sub,
				providerType: 'oidc',
				userId: newUser.id,
			}),
		);

		this.logger.debug(`OIDC login: Created new user ${email} with role ${role.slug}`);
		return newUser;
	}

	/**
	 * Extract roles from claims using the Keycloak-style path:
	 * resource_access.{clientId}.roles
	 */
	private extractRoles(claims: Record<string, unknown>): string[] {
		const clientId = this.instanceSettingsLoaderConfig.oidcClientId;
		if (!clientId) return [];

		const parts = ['resource_access', clientId, 'roles'];
		let value: unknown = claims;
		for (const part of parts) {
			if (value && typeof value === 'object') {
				value = (value as Record<string, unknown>)[part];
			} else {
				return [];
			}
		}

		if (Array.isArray(value)) return value.map(String);
		if (typeof value === 'string') return [value];
		return [];
	}

	/**
	 * Determine if any of the extracted roles should grant admin privileges.
	 * Defaults to matching 'admin' or any role containing 'admin' / 'owner'.
	 */
	private isAdminRole(roles: string[]): boolean {
		if (roles.length === 0) return false;

		const adminRoleEnv = process.env.N8N_SSO_OIDC_ADMIN_ROLE || 'admin';
		return roles.some(
			(role) =>
				role.toLowerCase() === adminRoleEnv.toLowerCase() ||
				role.toLowerCase().includes('admin') ||
				role.toLowerCase().includes('owner'),
		);
	}
}
