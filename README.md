# certferry

Distribute Let's Encrypt wildcard certificates across servers without Ansible, puppet, or custom HTTP APIs. Just a single binary.

## The problem

You have a wildcard certificate for `*.yourdomain.com` issued by certbot on your main server. You have 10, 50, or 100 slave servers that need this certificate. Let's Encrypt rate limits make it impractical to issue separate certificates for each subdomain, and setting up Ansible just to copy a few files feels like overkill.

## How it works

SSL/TLS certificates are public — every server hands them out during the TLS handshake. certferry simply connects to your main server over TLS, extracts the certificate chain, and writes it to the standard certbot directory structure. No custom server, no authentication, no configuration.

## Setup

### 1. Main server: issue the wildcard certificate with certbot

```sh
certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  --agree-tos --no-eff-email --reuse-key \
  -m your@email.com \
  -d yourdomain.com \
  -d '*.yourdomain.com'
```

certbot handles automatic renewal. The private key stays on this server and is distributed to slaves through secure channels (e.g. initial provisioning, SSH).

### 2. Slave servers: fetch the certificate

```sh
certferry yourdomain.com
```

This connects to `yourdomain.com:443`, extracts the certificate chain, and writes:

- `/etc/letsencrypt/live/yourdomain.com/cert.pem` — leaf certificate
- `/etc/letsencrypt/live/yourdomain.com/chain.pem` — intermediate certificates
- `/etc/letsencrypt/live/yourdomain.com/fullchain.pem` — both combined

### 3. Automatic renewal

```sh
certferry --install
```

Creates a systemd timer that runs `certferry --renew` twice daily (like certbot). On each run, it checks all certificates in `/etc/letsencrypt/live/` and fetches fresh ones for any expiring within 29 days. If the fetched certificate is identical to the existing one, no files are written and no hooks are triggered.

After updating certificates, certferry runs all scripts in `/etc/letsencrypt/renewal-hooks/deploy/` with certbot-compatible environment variables (`RENEWED_LINEAGE`, `RENEWED_DOMAINS`), so your existing reload hooks (e.g. `systemctl reload nginx`) work as-is.

## Usage

```
certferry <domain>          # fetch certificate from domain:443
certferry <domain>:8443     # custom port
certferry https://domain    # https:// prefix also works

certferry --renew           # renew expiring certificates (29-day threshold)
certferry --renew --force   # renew all certificates unconditionally
certferry --install         # install systemd timer for automatic renewal
```

## Building

```sh
cargo build --release
sudo cp target/release/certferry /usr/local/bin/
```

## License

MIT
