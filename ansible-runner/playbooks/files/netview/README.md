# Sentry Lens

Traffic views for a home or small-office network, on top of [Akvorado](https://github.com/akvorado/akvorado)
(NetFlow/IPFIX into ClickHouse): devices by name, what each one talks to, websites and their
categories, internet vs LAN traffic, live throughput and flows, with drill-down from any chart.

Deployed by `playbooks/netview_stack.yml` as one container next to the Akvorado stack (it reads
Akvorado's ClickHouse and keeps its own small `netview` database there).

## Deploy

1. Akvorado: `./run.sh akvorado_stack.yml` (collector host, flow exporters - see that playbook).
2. Sentry Lens: `./run.sh netview_stack.yml`, after setting at least `netview_public_url` (the
   address people will use - also the base of every sign-in redirect URL).
3. Open the address. A fresh install shows **first-run setup**: create the administrator with the
   setup token from the server - `sudo grep SETUP_TOKEN /opt/netview/session.env` (root only).

Re-running the playbook updates in place; accounts, sign-in methods and data stay.

## Sign-in

Every page and API call needs a signed-in, **approved** account - the LAN address included.
New accounts wait on **Admin > Users** until an administrator approves them, unless their sign-in
method auto-approves. Accounts listed in `netview_admin_emails` are approved administrators as
soon as they sign in by any verified method.

Sign-in methods can be set in two places:

- **Admin > Sign-in methods** in the app: add, edit, test or remove them; secrets are encrypted
  at rest and never shown again.
- **`netview_auth_providers`** in the playbook (secrets from Ansible Vault): read-only in the app.

The app's **callback (redirect) URL** for a method is `<netview_public_url>/auth/callback/<id>`,
where `<id>` is the method's id (shown in Settings). Register exactly that with the provider.

| Type | Register the app at | What Sentry Lens needs |
|---|---|---|
| Local accounts | - | nothing: email + password on the login page, "Create an account" |
| Google | console.cloud.google.com > APIs & Services > Credentials > OAuth client ID (Web) | client ID, client secret |
| Microsoft Entra ID (Azure AD) | entra.microsoft.com > App registrations > New (Web redirect URI) | tenant ID (or `common`), application (client) ID, client secret |
| Apple | developer.apple.com > Identifiers > Services ID (Sign in with Apple), plus a key | services ID, team ID, key ID, the `.p8` private key (needs HTTPS) |
| GitHub | github.com/settings/developers > New OAuth App | client ID, client secret |
| AWS Cognito | Cognito user pool > App client (hosted UI, OIDC scopes `openid email profile`) | region, user pool ID, app client ID (+ secret) - federate IAM Identity Center or SAML directories into the pool |
| OpenID Connect | any OIDC server: Okta, Auth0, Keycloak, Authentik, Ping, Zitadel... | issuer URL, client ID, client secret |
| LDAP / Active Directory | - | server URL, bind DN + password (service account), base DN; optional user filter, email / name attributes, required group DN |

Per method: **allowed email domains** (only those can sign in through it) and **auto-approve**
(trust the directory, skip the approval queue).

LDAP users sign in on the normal password form with their directory username or email; the app
binds as the service account, finds the user (`{login}` in the filter is what they typed,
escaped), checks the required group (`memberOf`), then binds as the user to check the password.

Example `netview_auth_providers` (secrets from the vault):

```yaml
netview_auth_providers:
  - {id: google, type: google, client_id: "123-abc.apps.googleusercontent.com",
     client_secret: "{{ vault_lens_google_secret }}"}
  - {id: entra, type: microsoft, tenant: "00000000-0000-0000-0000-000000000000",
     client_id: "11111111-...", client_secret: "{{ vault_lens_entra_secret }}",
     allowed_domains: "example.com", auto_approve: true}
  - {id: corp, type: ldap, name: Corp AD, url: "ldaps://dc1.corp.example.com",
     bind_dn: "CN=svc-lens,OU=Service,DC=corp,DC=example,DC=com",
     bind_password: "{{ vault_lens_ldap_bind }}", base_dn: "DC=corp,DC=example,DC=com",
     group_dn: "CN=Sentry Lens Users,OU=Groups,DC=corp,DC=example,DC=com", auto_approve: true}
```

### Behind an identity proxy instead

`netview_auth_methods: [builtin, cloudflare]` also accepts a Cloudflare Access token (set
`netview_cf_team` / `netview_cf_aud`; `cloudflare_access.yml` creates the Access application and
brands its login page). `[cloudflare]` alone = only Access; `[off]` = no sign-in (LAN only).

### Security notes

- Passwords: scrypt (N=2^14, r=8, p=1, per-account salt). Sign-in throttled per address
  (8 failures / 5 min). Session cookies signed, HttpOnly, SameSite=Lax, Secure on HTTPS.
- OAuth/OIDC: state, nonce and PKCE (S256); ID tokens verified against the provider's keys,
  audience, issuer and nonce; unverified emails refused.
- The session secret (`/opt/netview/session.env`, made once) also keys the encryption of secrets
  stored from the Settings page: replacing it signs everyone out and those secrets must be
  entered again.
- Accounts and stored methods live in ClickHouse (`netview.users`, `netview.auth_methods`) - back
  up the ClickHouse volume, or keep providers in the playbook.

## Data sources (optional parts)

- Device names: the firewall's DHCP leases and Tailscale peers (OPNsense API).
- Websites: the firewall's DNS query log (Unbound), categories from the UT1 blacklists
  (Universite Toulouse Capitole, CC BY-SA 4.0), refreshed daily.
- Live page: the firewall's interface counters and top talkers (OPNsense API).
