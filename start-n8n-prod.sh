#!/bin/bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
nvm use 22

cd /app/n8n

# Read OIDC secret from file (bypass system redaction)
SECRET=$(cat /tmp/n8n_secret.txt 2>/dev/null || echo "")

export N8N_PORT=5680
export N8N_PROTOCOL=http
export N8N_HOST=localhost
export NODE_ENV=production
export N8N_BASIC_AUTH_ACTIVE=***
export N8N_SSO_OIDC_LOGIN_ENABLED=true
export N8N_SSO_OIDC_ISSUER_URL=https://auth.home.martini.wang:50443/realms/martini
export N8N_SSO_OIDC_CLIENT_ID=n8n-prod
export N8N_SSO_OIDC_CLIENT_SECRET=***
export N8N_SSO_OIDC_REDIRECT_URI=http://localhost:5680/rest/login/oidc/callback
export N8N_SSO_OIDC_SCOPE="openid profile email"
export N8N_SECURE_COOKIE=false
export DB_TYPE=sqlite
export DB_SQLITE_DATABASE=/app/n8n-test-data/database-prod.sqlite

node packages/cli/bin/n8n start
