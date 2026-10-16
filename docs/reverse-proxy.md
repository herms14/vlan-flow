# Reverse proxy, HTTPS and login

VLAN Flow has **no login of its own**. If anyone other than you can reach port 8787, put it behind a
reverse proxy that adds authentication, and let only the proxy reach VLAN Flow.

In every example:

- VLAN Flow runs at `192.168.20.50:8787`. Replace it with your server.
- The public name is `vlanflow.example.com`. Add that name to `allowed_hosts` in `config.json`.
- Restrict port 8787 on the VLAN Flow server to the proxy's IP (see the firewall section of
  [omada-setup.md](omada-setup.md#firewall-on-the-vlan-flow-server)).

---

## Caddy (automatic HTTPS + basic auth)

```caddy
vlanflow.example.com {
    basic_auth {
        # Create the hash with: caddy hash-password
        admin <paste-the-hash-here>
    }
    reverse_proxy 192.168.20.50:8787
}
```

## nginx (basic auth)

```sh
sudo apt install apache2-utils
sudo htpasswd -c /etc/nginx/vlanflow.htpasswd admin
```

```nginx
server {
    listen 443 ssl;
    server_name vlanflow.example.com;
    # ssl_certificate / ssl_certificate_key: your certificate

    auth_basic "VLAN Flow";
    auth_basic_user_file /etc/nginx/vlanflow.htpasswd;

    location / {
        proxy_pass http://192.168.20.50:8787;
        proxy_set_header Host $host;
    }
}
```

## Traefik (file provider)

```yaml
http:
  routers:
    vlanflow:
      rule: Host(`vlanflow.example.com`)
      entryPoints: [websecure]
      service: vlanflow
      middlewares: [vlanflow-auth]   # or your SSO forward-auth middleware (Authentik, Authelia)
      tls:
        certResolver: letsencrypt
  middlewares:
    vlanflow-auth:
      basicAuth:
        users:
          - "admin:<htpasswd-hash>"   # htpasswd -nB admin
  services:
    vlanflow:
      loadBalancer:
        servers:
          - url: http://192.168.20.50:8787
        healthCheck:
          path: /healthz
          interval: 30s
```

## Single sign-on

Any forward-auth provider works the same way: Authentik, Authelia, oauth2-proxy, Cloudflare
Access, Tailscale Serve. Protect the whole host name; VLAN Flow needs no extra configuration.
