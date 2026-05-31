# SHROUD docker-compose deployment

Self-host the full SHROUD stack on a single Linux box with Docker.
No AWS, no Terraform, no Kubernetes. The relay + SFU run as two
containers on a shared bridge network; storage persists to a named
Docker volume.

## Requirements

- Docker 24+ with Compose v2
- Ports 58443 (relay) and 58444 (SFU) reachable from clients
- TLS cert — either bring your own and mount into `./certs/`, or
  let the relay generate a self-signed cert on first boot

## Bring up

```bash
cd deploy/docker-compose
docker compose up -d
docker compose logs -f relay   # watch boot
```

The relay's `/health` should respond within ~30 seconds:

```bash
curl -k https://localhost:58443/health
```

## Tear down

Preserve message-queue volume (so users keep their state if you
update the container):

```bash
docker compose down
```

Nuke everything:

```bash
docker compose down --volumes
```

## Enable federation

Create a `.env` file alongside `docker-compose.yml`:

```
SHROUD_FEDERATION=1
```

Then re-up. The relay will start the federation gossip loop. Use
`tools/federation_join.py` to onboard peers.

## Adding a real TLS cert (Let's Encrypt)

Mount a Nginx reverse proxy in front. Uncomment the `nginx:` block
in `docker-compose.yml` and drop your `fullchain.pem` + `privkey.pem`
into `./certs/`. Edit the `nginx.conf` (sample below) to forward
`/` traffic to the `relay` service.

```nginx
events {}
http {
    server {
        listen 443 ssl http2;
        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
        client_max_body_size 32M;
        location / {
            proxy_pass https://relay:58443;
            proxy_ssl_verify off;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
```

## Cost

- ~$5/mo VPS (Hetzner CX22, Vultr regular, OVH eco) is plenty for a
  small relay
- No AWS lock-in, no Terraform state, no Cloud Act risk

This is the recommended setup for users who don't want AWS-specific
attestation but want full Rule 0 (non-US legal exposure, multi-
operator federation).
