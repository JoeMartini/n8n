![Banner image](https://user-images.githubusercontent.com/10284570/173569848-c624317f-42b1-45a6-ab09-f0ea3c247648.png)

# n8n – The Platform for AI Agents and Workflow Automation

> 🍴 **This fork adds Community OIDC SSO integration** — authenticate users via Keycloak (or any OIDC provider) without requiring an Enterprise license. See [OIDC Integration](#oidc-integration) below.

Fair-code platform to build and deploy AI agents and workflows. Combine a visual canvas with custom code, run it self-hosted or in the [cloud](https://app.n8n.cloud/login), and connect to 1500+ integrations. AI automation you can trust with real work, from prototype to production.

![n8n.io - Screenshot](https://raw.githubusercontent.com/n8n-io/n8n/master/assets/n8n-screenshot-readme.png)

## Key Capabilities

- **AI-Native Automation Platform**: Build and operationalize AI workflows and multi-step agents using your own data, models, and tools
- **Model Flexibility, No Lock-In**: Connect to OpenAI, Anthropic, Google, or open-source models and switch providers without changing your architecture
- **From Prototype to Production**: Design multi-step AI workflows with logic, tool use, human approvals, and full observability
- **Code When You Need It**: Combine visual building with JavaScript, Python, and npm packages for advanced AI workflows
- **Enterprise-Ready AI**: Self-host or deploy securely with role-based access, audit trails, and support for sensitive data
- **Leverage What Already Exists**: 1500+ integrations and 9,000+ workflow [templates](https://n8n.io/workflows) to connect AI with your existing systems

## Quick Start

Try n8n instantly with [npx](https://docs.n8n.io/hosting/installation/npm/) (requires [Node.js](https://nodejs.org/en/)):

```
npx n8n
```

Or deploy with [Docker](https://docs.n8n.io/hosting/installation/docker/):

```
docker volume create n8n_data
docker run -it --rm --name n8n -p 5678:5678 -v n8n_data:/home/node/.n8n docker.n8n.io/n8nio/n8n
```

Access the editor at http://localhost:5678

## Resources

- 📚 [Documentation](https://docs.n8n.io)
- 🔧 [1500+ Integrations](https://n8n.io/integrations)
- 💡 [Example Workflows](https://n8n.io/workflows)
- 🤖 [AI & LangChain Guide](https://docs.n8n.io/advanced-ai/)
- 👥 [Community Forum](https://community.n8n.io)
- 📖 [Community Tutorials](https://community.n8n.io/c/tutorials/28)

## Support

Need help? Our community forum is the place to get support and connect with other users:
[community.n8n.io](https://community.n8n.io)

## License

n8n is [fair-code](https://faircode.io) distributed under the [Sustainable Use License](https://github.com/n8n-io/n8n/blob/master/LICENSE.md) and [n8n Enterprise License](https://github.com/n8n-io/n8n/blob/master/LICENSE_EE.md).

- **Source Available**: Always visible source code
- **Self-Hostable**: Deploy anywhere
- **Extensible**: Add your own nodes and functionality

[Enterprise Licenses](mailto:license@n8n.io) available for additional features and support.

Additional information about the license model can be found in the [docs](https://docs.n8n.io/sustainable-use-license/).

## Contributing

Found a bug 🐛 or have a feature idea ✨? Check our [Contributing Guide](https://github.com/n8n-io/n8n/blob/master/CONTRIBUTING.md) for a setup guide & best practices.

## Join the Team

Want to shape the future of automation? Check out our [job posts](https://n8n.io/careers) and join our team!

## What does n8n mean?

**Short answer:** It means "nodemation" and is pronounced as n-eight-n.

**Long answer:** "I get that question quite often (more often than I expected) so I decided it is probably best to answer it here. While looking for a good name for the project with a free domain I realized very quickly that all the good ones I could think of were already taken. So, in the end, I chose nodemation. 'node-' in the sense that it uses a Node-View and that it uses Node.js and '-mation' for 'automation' which is what the project is supposed to help with. However, I did not like how long the name was and I could not imagine writing something that long every time in the CLI. That is when I then ended up on 'n8n'." - **Jan Oberhauser, Founder and CEO, n8n.io**

---

## OIDC Integration

This fork (`community-oidc`) adds **OIDC Single Sign-On for the Community Edition**, removing the Enterprise license requirement.

### What was changed

- **Frontend** (`packages/editor-ui/src/views/SigninView.vue`):
  - Introduced `oidc_full` mode: hides username/password inputs entirely, showing only a single SSO login button
  - Added `oidc` mixed mode: keeps local login as fallback while adding SSO option
  - Unified SSO button label to "🔐 统一身份登录" with consistent styling

- **SSO Component** (`packages/editor-ui/src/components/SSOLogin.vue`):
  - Enhanced to support external OIDC providers via the existing generic OAuth2 framework
  - Properly handles `redirect_uri` and `state` parameters for secure callback flow

- **Backend** (`packages/cli/src/commands/oauth/oauth2-credential.controller.ts`):
  - Exposes frontend-configurable OIDC settings via existing endpoints
  - Role mapping from Keycloak `groups` claim to n8n user roles

### How to use

1. Build n8n from this branch
2. Set environment variables:
   - `N8N_SSO_OIDC_CLIENT_ID`
   - `N8N_SSO_OIDC_CLIENT_SECRET`
   - `N8N_SSO_OIDC_ISSUER_URI` (e.g., `https://auth.example.com/realms/myrealm`)
   - `N8N_SSO_OIDC_REDIRECT_URI` (e.g., `https://n8n.example.com/rest/oauth2-credential/callback`)
3. Choose mode via `N8N_SSO_OIDC_MODE=oidc_full` or `oidc`
4. Start n8n and users will see the SSO login button

### Branches in this fork

| Branch | Purpose |
|--------|---------|
| `master` | Tracks upstream n8n master |
| `community-oidc` | Community OIDC SSO integration |

### Author

Maintained by [Hermes-Martini-Home](https://github.com/JoeMartini) · [Upstream sync record](https://app.notion.com/p/37fc7ae4e85381f890e0f65a70cc8b29)
