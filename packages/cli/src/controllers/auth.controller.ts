import { LoginRequestDto, ResolveSignupTokenQueryDto } from '@n8n/api-types';
import { Logger } from '@n8n/backend-common';
import { Time } from '@n8n/constants';
import type { User, PublicUser, AuthProviderType } from '@n8n/db';
import {
	AuthIdentityRepository,
	UserRepository,
	AuthenticatedRequest,
	GLOBAL_ADMIN_ROLE,
	GLOBAL_MEMBER_ROLE,
	GLOBAL_OWNER_ROLE,
	isValidEmail,
} from '@n8n/db';
import {
	Body,
	createBodyKeyedRateLimiter,
	Get,
	Post,
	Query,
	RestController,
} from '@n8n/decorators';
import { GlobalConfig } from '@n8n/config';
import { isEmail } from 'class-validator';
import { Response } from 'express';
import { randomUUID } from 'crypto';

import { AuthHandlerRegistry } from '@/auth/auth-handler.registry';
import { AuthService } from '@/auth/auth.service';
import {
	OIDC_NONCE_COOKIE_NAME,
	OIDC_STATE_COOKIE_NAME,
	RESPONSE_ERROR_MESSAGES,
} from '@/constants';
import { AuthError } from '@/errors/response-errors/auth.error';
import { BadRequestError } from '@/errors/response-errors/bad-request.error';
import { ForbiddenError } from '@/errors/response-errors/forbidden.error';
import { InternalServerError } from '@/errors/response-errors/internal-server.error';
import { EventService } from '@/events/event.service';
import { License } from '@/license';
import { MfaService } from '@/mfa/mfa.service';
import { PostHogClient } from '@/posthog';
import { AuthlessRequest } from '@/requests';
import { JwtService } from '@/services/jwt.service';
import { UrlService } from '@/services/url.service';
import { UserService } from '@/services/user.service';
import {
	getCurrentAuthenticationMethod,
	isOidcCurrentAuthenticationMethod,
	isSamlCurrentAuthenticationMethod,
	isSsoCurrentAuthenticationMethod,
} from '@/sso.ee/sso-helpers';
import '../auth/handlers/email.auth-handler';

@RestController()
export class AuthController {
	constructor(
		private readonly logger: Logger,
		private readonly authService: AuthService,
		private readonly mfaService: MfaService,
		private readonly userService: UserService,
		private readonly license: License,
		private readonly userRepository: UserRepository,
		private readonly authIdentityRepository: AuthIdentityRepository,
		private readonly eventService: EventService,
		private readonly authHandlerRegistry: AuthHandlerRegistry,
		private readonly globalConfig: GlobalConfig,
		private readonly jwtService: JwtService,
		private readonly urlService: UrlService,
		private readonly postHog?: PostHogClient,
	) {}

	/** Log in a user */
	@Post('/login', {
		skipAuth: true,
		// Two layered rate limit to ensure multiple users can login from the same
		// IP address but aggressive per email limit.
		ipRateLimit: {
			limit: 1000,
			windowMs: 5 * Time.minutes.toMilliseconds,
		},
		keyedRateLimit: createBodyKeyedRateLimiter<LoginRequestDto>({
			limit: 5,
			windowMs: 1 * Time.minutes.toMilliseconds,
			field: 'emailOrLdapLoginId',
		}),
	})
	async login(
		req: AuthlessRequest,
		res: Response,
		@Body payload: LoginRequestDto,
	): Promise<PublicUser | undefined> {
		const { emailOrLdapLoginId, password, mfaCode, mfaRecoveryCode } = payload;

		const currentAuthenticationMethod = getCurrentAuthenticationMethod();
		this.validateEmailFormat(currentAuthenticationMethod, emailOrLdapLoginId);

		const emailHandler = this.authHandlerRegistry.get('email', 'password');
		if (!emailHandler) {
			this.logger.error('Email authentication handler is not registered');
			throw new InternalServerError('Email authentication method not available');
		}

		const preliminaryUser = await emailHandler.handleLogin(emailOrLdapLoginId, password);
		this.validateSsoRestrictions(preliminaryUser, emailOrLdapLoginId);

		const { user, usedAuthenticationMethod } = await this.authenticateWithPassword(
			currentAuthenticationMethod,
			emailOrLdapLoginId,
			password,
			preliminaryUser,
		);

		await this.validateMfa(user, mfaCode, mfaRecoveryCode);

		this.authService.issueCookie(res, user, user.mfaEnabled, req.browserId);

		this.eventService.emit('user-logged-in', {
			user,
			authenticationMethod: usedAuthenticationMethod,
		});

		return await this.userService.toPublic(user, {
			posthog: this.postHog,
			withScopes: true,
			mfaAuthenticated: user.mfaEnabled,
		});
	}

	private validateEmailFormat(authMethod: AuthProviderType, emailOrLdapLoginId: string): void {
		if (authMethod === 'email' && !isEmail(emailOrLdapLoginId)) {
			throw new BadRequestError('Invalid email address');
		}
	}

	private validateSsoRestrictions(preliminaryUser: User | undefined, userEmail: string): void {
		const shouldBlockSsoUser =
			(isSamlCurrentAuthenticationMethod() || isOidcCurrentAuthenticationMethod()) &&
			preliminaryUser?.role.slug !== GLOBAL_OWNER_ROLE.slug &&
			!preliminaryUser?.settings?.allowSSOManualLogin;

		if (shouldBlockSsoUser) {
			this.eventService.emit('user-login-failed', {
				authenticationMethod: 'email',
				userEmail,
				reason: 'SSO is enabled, please log in with SSO',
			});
			throw new AuthError('SSO is enabled, please log in with SSO');
		}
	}

	private async authenticateWithPassword(
		getCurrentAuthenticationMethod: AuthProviderType,
		emailOrLdapLoginId: string,
		password: string,
		preliminaryUser: User | undefined,
	): Promise<{ user: User; usedAuthenticationMethod: AuthProviderType }> {
		let user = preliminaryUser;
		let usedAuthenticationMethod: AuthProviderType = 'email';

		const shouldTryAlternativeAuth =
			getCurrentAuthenticationMethod !== 'email' &&
			preliminaryUser?.role.slug !== GLOBAL_OWNER_ROLE.slug;

		if (shouldTryAlternativeAuth) {
			const authHandler = this.authHandlerRegistry.get(getCurrentAuthenticationMethod, 'password');
			if (authHandler) {
				user = await authHandler.handleLogin(emailOrLdapLoginId, password);
				usedAuthenticationMethod = getCurrentAuthenticationMethod;
			}
		}

		if (!user) {
			this.eventService.emit('user-login-failed', {
				authenticationMethod: usedAuthenticationMethod,
				userEmail: emailOrLdapLoginId,
				reason: 'wrong credentials',
			});
			throw new AuthError('Wrong username or password. Do you have caps lock on?');
		}

		return { user, usedAuthenticationMethod };
	}

	private async validateMfa(
		user: User,
		mfaCode: string | undefined,
		mfaRecoveryCode: string | undefined,
	): Promise<void> {
		if (!user.mfaEnabled) {
			return;
		}

		if (!mfaCode && !mfaRecoveryCode) {
			throw new AuthError('MFA Error', 998);
		}

		const isMfaCodeOrMfaRecoveryCodeValid = await this.mfaService.validateMfa(
			user.id,
			mfaCode,
			mfaRecoveryCode,
		);

		if (!isMfaCodeOrMfaRecoveryCodeValid) {
			throw new AuthError('Invalid mfa token or recovery code');
		}
	}

	/** Check if the user is already logged in */
	@Get('/login', {
		allowSkipMFA: true,
	})
	async currentUser(req: AuthenticatedRequest): Promise<PublicUser> {
		// We need auth identities to determine signInType in toPublic method
		const user = await this.userService.findUserWithAuthIdentities(req.user.id);

		return await this.userService.toPublic(user, {
			posthog: this.postHog,
			withScopes: true,
			mfaAuthenticated: req.authInfo?.usedMfa,
		});
	}

	/** Redirect to OIDC identity provider for community edition SSO */
	@Get('/login/oidc', { skipAuth: true })
	async oidcLogin(_req: AuthlessRequest, res: Response) {
		const oidcConfig = this.globalConfig.sso.oidc;
		if (
			!oidcConfig.loginEnabled ||
			!oidcConfig.issuerUrl ||
			!oidcConfig.clientId ||
			!oidcConfig.clientSecret
		) {
			this.logger.error('OIDC login is not configured');
			throw new BadRequestError('OIDC login is not configured');
		}

		const openidClient = await import('openid-client');
		const issuerUrl = new URL(oidcConfig.issuerUrl);
		const configuration = await openidClient.discovery(issuerUrl, oidcConfig.clientId, {
			client_secret: oidcConfig.clientSecret,
		});

		const state = this.generateOidcState();
		const nonce = this.generateOidcNonce();

		const redirectUri =
			oidcConfig.redirectUri ||
			`${this.urlService.getInstanceBaseUrl()}/${this.globalConfig.endpoints.rest}/login/oidc/callback`;

		const authorizationURL = openidClient.buildAuthorizationUrl(configuration, {
			redirect_uri: redirectUri,
			response_type: 'code',
			scope: 'openid email profile',
			state: state.plaintext,
			nonce: nonce.plaintext,
		});

		const { samesite, secure } = this.globalConfig.auth.cookie;
		res.cookie(OIDC_STATE_COOKIE_NAME, state.signed, {
			maxAge: 15 * Time.minutes.toMilliseconds,
			httpOnly: true,
			sameSite: samesite,
			secure,
		});
		res.cookie(OIDC_NONCE_COOKIE_NAME, nonce.signed, {
			maxAge: 15 * Time.minutes.toMilliseconds,
			httpOnly: true,
			sameSite: samesite,
			secure,
		});

		res.redirect(authorizationURL.toString());
	}

	/** Handle OIDC callback for community edition SSO */
	@Get('/login/oidc/callback', { skipAuth: true })
	async oidcCallback(req: AuthlessRequest, res: Response) {
		try {
			const oidcConfig = this.globalConfig.sso.oidc;
			const fullUrl = `${this.urlService.getInstanceBaseUrl()}${req.originalUrl}`;
			const callbackUrl = new URL(fullUrl);

			const state = req.cookies[OIDC_STATE_COOKIE_NAME];
			if (typeof state !== 'string') {
				this.logger.error('State is missing');
				return res.status(400).json({ status: 'error', message: 'Invalid state' });
			}

			const nonce = req.cookies[OIDC_NONCE_COOKIE_NAME];
			if (typeof nonce !== 'string') {
				this.logger.error('Nonce is missing');
				return res.status(400).json({ status: 'error', message: 'Invalid nonce' });
			}

			let expectedState: string;
			let expectedNonce: string;
			try {
				const stateResult = this.verifyOidcState(state);
				expectedState = stateResult.expectedState;
				expectedNonce = this.verifyOidcNonce(nonce);
			} catch {
				return res.status(400).json({ status: 'error', message: 'Invalid state or nonce' });
			}

			res.clearCookie(OIDC_STATE_COOKIE_NAME);
			res.clearCookie(OIDC_NONCE_COOKIE_NAME);

			// Extract code from callback URL
			const code = callbackUrl.searchParams.get('code');
			if (!code) {
				return res.status(400).json({ status: 'error', message: 'Missing authorization code' });
			}

			// Verify state matches
			const returnedState = callbackUrl.searchParams.get('state');
			if (returnedState !== expectedState) {
				return res.status(400).json({ status: 'error', message: 'Invalid state' });
			}

			// Exchange code for tokens manually using client_secret_post
			const tokenEndpoint = `${oidcConfig.issuerUrl}/protocol/openid-connect/token`;
			const redirectUri =
				oidcConfig.redirectUri ||
				`${this.urlService.getInstanceBaseUrl()}/${this.globalConfig.endpoints.rest}/login/oidc/callback`;

			const tokenResponse = await fetch(tokenEndpoint, {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					grant_type: 'authorization_code',
					client_id: oidcConfig.clientId,
					client_secret: oidcConfig.clientSecret,
					code,
					redirect_uri: redirectUri,
				}),
			});

			if (!tokenResponse.ok) {
				const errorBody = await tokenResponse.text();
				this.logger.error('Token exchange failed', {
					status: tokenResponse.status,
					body: errorBody,
				});
				return res
					.status(400)
					.json({ status: 'error', message: 'Failed to exchange authorization code' });
			}

			const tokenData = await tokenResponse.json();

			// Parse JWT id_token
			let claims: Record<string, unknown>;
			try {
				const idToken = tokenData.id_token as string;
				const [, payloadB64] = idToken.split('.');
				const payloadJson = Buffer.from(payloadB64, 'base64url').toString('utf8');
				claims = JSON.parse(payloadJson);
			} catch (error) {
				this.logger.error('Failed to parse id_token', { error });
				return res.status(400).json({ status: 'error', message: 'Invalid token' });
			}

			// Verify nonce
			if (claims.nonce !== expectedNonce) {
				return res.status(400).json({ status: 'error', message: 'Invalid nonce' });
			}

			if (!claims.sub) {
				return res
					.status(403)
					.json({ status: 'error', message: 'No subject found in the OIDC token' });
			}

			// Build userInfo from id_token claims
			const userInfo = {
				email: claims.email as string | undefined,
				given_name: claims.given_name as string | undefined,
				family_name: claims.family_name as string | undefined,
				name: claims.name as string | undefined,
			};

			if (!userInfo.email) {
				return res.status(400).json({ status: 'error', message: 'An email is required' });
			}

			if (!isValidEmail(userInfo.email)) {
				return res.status(400).json({ status: 'error', message: 'Invalid email format' });
			}

			const user = await this.findOrCreateOidcUser(claims.sub as string, userInfo);
			await this.applyOidcRoleMapping(user, claims);

			this.authService.issueCookie(res, user, true, req.browserId);
			this.eventService.emit('user-logged-in', {
				user,
				authenticationMethod: 'oidc',
			});

			return res.redirect('/');
		} catch (error) {
			this.logger.error('OIDC callback failed', { error });
			if (!res.headersSent) {
				return res.status(500).json({ status: 'error', message: 'Internal server error' });
			}
		}
	}

	private generateOidcState() {
		const state = `n8n_state:${randomUUID()}`;
		return {
			signed: this.jwtService.sign({ state }, { expiresIn: '15m' }),
			plaintext: state,
		};
	}

	private verifyOidcState(signedState: string): { expectedState: string } {
		try {
			const decoded = this.jwtService.verify(signedState);
			if (typeof decoded?.state !== 'string') {
				throw new BadRequestError('Invalid state');
			}
			return { expectedState: decoded.state };
		} catch {
			throw new BadRequestError('Invalid state');
		}
	}

	private generateOidcNonce() {
		const nonce = `n8n_nonce:${randomUUID()}`;
		return {
			signed: this.jwtService.sign({ nonce }, { expiresIn: '15m' }),
			plaintext: nonce,
		};
	}

	private verifyOidcNonce(signedNonce: string): string {
		try {
			const decoded = this.jwtService.verify(signedNonce);
			if (typeof decoded?.nonce !== 'string') {
				throw new BadRequestError('Invalid nonce');
			}
			return decoded.nonce;
		} catch {
			throw new BadRequestError('Invalid nonce');
		}
	}

	private async findOrCreateOidcUser(providerId: string, userInfo: any): Promise<User> {
		const openidUser = await this.authIdentityRepository.findOne({
			where: { providerId, providerType: 'oidc' },
			relations: {
				user: {
					role: true,
				},
			},
		});

		if (openidUser) {
			return openidUser.user;
		}

		const foundUser = await this.userRepository.findOne({
			where: { email: userInfo.email },
			relations: ['authIdentities', 'role'],
		});

		if (foundUser) {
			this.logger.debug(
				`OIDC login: User with email ${userInfo.email} already exists, linking OIDC identity.`,
			);
			const id = this.authIdentityRepository.create({
				providerId,
				providerType: 'oidc',
				userId: foundUser.id,
			});
			await this.authIdentityRepository.save(id);
			return foundUser;
		}

		const oidcConfig = this.globalConfig.sso.oidc;
		if (!oidcConfig.autoProvision && !this.globalConfig.sso.justInTimeProvisioning) {
			throw new ForbiddenError('User not found and auto-provisioning is disabled');
		}

		const { user: newUser } = await this.userRepository.createUserWithProject({
			firstName: userInfo.given_name || userInfo.name?.split(' ')[0] || '',
			lastName: userInfo.family_name || userInfo.name?.split(' ').slice(1).join(' ') || '',
			email: userInfo.email,
			authIdentities: [],
			role: GLOBAL_MEMBER_ROLE,
			password: 'no password set',
		});

		await this.authIdentityRepository.save(
			this.authIdentityRepository.create({
				providerId,
				providerType: 'oidc',
				userId: newUser.id,
			}),
		);

		return newUser;
	}

	private async applyOidcRoleMapping(user: User, claims: Record<string, unknown>): Promise<void> {
		const oidcConfig = this.globalConfig.sso.oidc;
		if (!oidcConfig.adminRole) {
			return;
		}

		const roles = this.extractOidcRoles(claims);
		if (roles.length === 0) {
			return;
		}

		const isAdmin = roles.includes(oidcConfig.adminRole);

		if (isAdmin && user.role.slug !== GLOBAL_ADMIN_ROLE.slug) {
			await this.userRepository.update(user.id, { role: GLOBAL_ADMIN_ROLE });
			user.role = GLOBAL_ADMIN_ROLE;
		}
	}

	/**
	 * Extract roles from OIDC claims.
	 * Supports Keycloak-style resource_access.{clientId}.roles
	 * and generic claim-based roles.
	 */
	private extractOidcRoles(claims: Record<string, unknown>): string[] {
		const oidcConfig = this.globalConfig.sso.oidc;

		// 1. Try Keycloak-style resource_access.{clientId}.roles
		if (oidcConfig.clientId) {
			const resourceAccess = claims.resource_access as
				| Record<string, { roles?: string[] }>
				| undefined;
			if (resourceAccess?.[oidcConfig.clientId]?.roles) {
				return resourceAccess[oidcConfig.clientId].roles!;
			}
		}

		// 2. Try generic role claim
		if (oidcConfig.roleClaim) {
			const roleValue = claims[oidcConfig.roleClaim];
			if (Array.isArray(roleValue)) {
				return roleValue.map(String);
			}
			if (typeof roleValue === 'string') {
				return [roleValue];
			}
		}

		return [];
	}

	/** Validate invite token to enable invitee to set up their account */
	@Get('/resolve-signup-token', { skipAuth: true })
	async resolveSignupToken(
		_req: AuthlessRequest,
		_res: Response,
		@Query payload: ResolveSignupTokenQueryDto,
	) {
		if (isSsoCurrentAuthenticationMethod()) {
			this.logger.debug(
				'Invite links are not supported on this system, please use single sign on instead.',
			);
			throw new BadRequestError(
				'Invite links are not supported on this system, please use single sign on instead.',
			);
		}

		if (!payload.token) {
			this.logger.debug('Request to resolve signup token failed because token is missing');
			throw new BadRequestError('Token is required');
		}

		const { inviterId, inviteeId } = await this.userService.getInvitationIdsFromPayload(
			payload.token,
		);

		const isWithinUsersLimit = this.license.isWithinUsersLimit();
		if (!isWithinUsersLimit) {
			this.logger.debug('Request to resolve signup token failed because of users quota reached', {
				inviterId,
				inviteeId,
			});
			throw new ForbiddenError(RESPONSE_ERROR_MESSAGES.USERS_QUOTA_REACHED);
		}

		const users = await this.userRepository.findManyByIds([inviterId, inviteeId], {
			includeRole: true,
		});

		if (users.length !== 2) {
			this.logger.debug(
				'Request to resolve signup token failed because the ID of the inviter and/or the ID of the invitee were not found in database',
				{ inviterId, inviteeId },
			);
			throw new BadRequestError('Invalid invite URL');
		}

		const invitee = users.find((user) => user.id === inviteeId);
		if (!invitee || invitee.password) {
			this.logger.error('Invalid invite URL - invitee already setup', {
				inviterId,
				inviteeId,
			});
			throw new BadRequestError('The invitation was likely either deleted or already claimed');
		}

		const inviter = users.find((user) => user.id === inviterId);
		if (!inviter?.email) {
			this.logger.error(
				'Request to resolve signup token failed because inviter does not exist or is not set up',
				{
					inviterId: inviter?.id,
				},
			);
			throw new BadRequestError('Invalid request');
		}

		this.eventService.emit('user-invite-email-click', { inviter, invitee });

		const { firstName, lastName } = inviter;
		return { inviter: { firstName, lastName } };
	}

	/** Log out a user */
	@Post('/logout')
	async logout(req: AuthenticatedRequest, res: Response) {
		await this.authService.invalidateToken(req);
		this.authService.clearCookie(res);
		return { loggedOut: true };
	}
}
