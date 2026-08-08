<script lang="ts" setup>
import { computed } from 'vue';
import { useSSOStore } from '../sso.store';
import { useI18n } from '@n8n/i18n';
import { useToast } from '@n8n/composables/useToast';
import { useRoute } from 'vue-router';

import { N8nButton } from '@n8n/design-system';
const i18n = useI18n();
const ssoStore = useSSOStore();
const toast = useToast();
const route = useRoute();

// Full OIDC mode: no local login form above, hide divider
const isFullMode = computed(() => ssoStore.isCommunityOidcEnabled);

const onSSOLogin = async () => {
	try {
		const redirectUrl = ssoStore.isDefaultAuthenticationSaml
			? await ssoStore.getSSORedirectUrl(
					typeof route.query?.redirect === 'string' ? route.query.redirect : '',
				)
			: ssoStore.oidcLoginUrl;
		window.location.href = redirectUrl ?? '';
	} catch (error) {
		toast.showError(error, 'Error', { message: error.message });
	}
};
</script>

<template>
	<div
		v-if="ssoStore.showSsoLoginButton || ssoStore.isCommunityOidcEnabled"
		:class="[$style.ssoLogin, isFullMode && $style.ssoLoginFull]"
	>
		<!-- Divider only shown in hybrid mode (local login form exists above) -->
		<div v-if="!isFullMode" :class="$style.divider">
			<span>{{ i18n.baseText('sso.login.divider') }}</span>
		</div>
		<N8nButton
			variant="outline"
			size="large"
			label="🔐 统一身份登录"
			:class="$style.ssoButton"
			@click="onSSOLogin"
		/>
	</div>
</template>

<style lang="scss" module>
.ssoLogin {
	display: flex;
	flex-direction: column;
	justify-content: center;
	align-items: center;
	text-align: center;
}

.ssoLoginFull {
	width: 100%;
	min-height: 120px;
	padding: var(--spacing--xl) 0;
}

.ssoButton {
	width: 100%;
	max-width: 320px;
}

.divider {
	width: 100%;
	position: relative;
	text-transform: uppercase;

	&::before {
		content: '';
		position: absolute;
		top: 50%;
		left: 0;
		width: 100%;
		height: 1px;
		background-color: var(--color--foreground);
	}

	span {
		position: relative;
		display: inline-block;
		margin: var(--spacing--2xs) auto;
		padding: var(--spacing--lg);
		background: var(--color--background--light-3);
	}
}
</style>
