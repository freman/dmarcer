# dmarcer

A self-contained DMARC report analyser. Single binary, no external services required.

Point it at an IMAP mailbox, open a browser, and you have a working DMARC dashboard.

## Quick start

```sh
DMARCER_IMAP_HOST=mail.example.com \
DMARCER_IMAP_USER=dmarc@example.com \
DMARCER_IMAP_PASSWORD=secret \
./dmarcer
```

Dashboard available at `http://localhost:8080`.

## Features

- Parses all three report types: aggregate (rua), forensic (ruf), and SMTP TLS (RFC 8460)
- IMAP ingestion with poll or IDLE watch mode
- HTTP file upload endpoint
- CLI batch ingest of files and directories
- SQLite storage - no separate database process
- Optional forwarding to Elasticsearch or OpenObserve
- Embedded GeoIP, sender map, and web UI - no runtime dependencies

## Build

Requires Go 1.26+.

```sh
go build ./cmd/dmarcer
```

## Configuration

All settings are environment variables with the `DMARCER_` prefix. Optionally, create a `.env` file in the working directory; real environment variables always override `.env` values.

### Minimum required

| Variable | Description |
|---|---|
| `DMARCER_IMAP_HOST` | IMAP server hostname - setting this enables IMAP ingestion |
| `DMARCER_IMAP_USER` | IMAP username |
| `DMARCER_IMAP_PASSWORD` | IMAP password |

### Common settings

| Variable | Default | Description |
|---|---|---|
| `DMARCER_HTTP_ADDR` | `:8080` | HTTP listen address |
| `DMARCER_DB_PATH` | `./dmarcer.db` | SQLite database file path |
| `DMARCER_API_KEY` | `` | Bearer token to protect the UI and API; empty = open |
| `DMARCER_IMAP_WATCH` | `false` | Use IMAP IDLE instead of polling |
| `DMARCER_IMAP_POLL_INTERVAL` | `5m` | Poll interval (Go duration string) |
| `DMARCER_IMAP_DELETE` | `false` | Delete processed messages; default is to archive |
| `DMARCER_OFFLINE` | `false` | Disable DNS and GeoIP lookups |

For the full configuration reference see `FSD.md` section 3.4, or the comments in `internal/config/config.go`.

### Duration variables

Time-based settings accept Go duration strings: `2s`, `5m`, `1h30m`, etc.

## Usage

```sh
# Start with .env file
./dmarcer

# IMAP IDLE (real-time instead of polling)
DMARCER_IMAP_WATCH=true ./dmarcer

# One-shot file ingest (no IMAP needed)
./dmarcer ingest /var/mail/dmarc-reports/

# Recursive directory ingest
./dmarcer ingest --recursive /var/mail/dmarc-reports/
```

## Docker

```sh
docker build -t dmarcer .
docker run -p 8080:8080 \
  -v $(pwd)/data:/data \
  -e DMARCER_IMAP_HOST=mail.example.com \
  -e DMARCER_IMAP_USER=dmarc@example.com \
  -e DMARCER_IMAP_PASSWORD=secret \
  dmarcer
```

Or with compose:

```yaml
services:
  dmarcer:
    image: dmarcer:latest
    ports:
      - "8080:8080"
    volumes:
      - ./data:/data
    env_file: [.env]
    restart: unless-stopped
```

## Elasticsearch / OpenObserve

Reports can additionally be forwarded to Elasticsearch or OpenObserve. The Elasticsearch index mappings are identical to parsedmarc's, so existing Kibana dashboards work against dmarcer data without modification.

```sh
# Elasticsearch
DMARCER_ES_URL=http://es:9200 ./dmarcer

# OpenObserve
DMARCER_OO_URL=http://openobserve:5080 \
DMARCER_OO_USER=root@example.com \
DMARCER_OO_PASSWORD=secret \
./dmarcer
```

## GeoIP database

A free DB-IP Country Lite database is bundled and used by default. For a more current or more detailed database, set `DMARCER_GEOIP_DB_PATH` to a MaxMind-format `.mmdb` file.

For automatic updates using a MaxMind account:

```sh
DMARCER_GEOIP_ACCOUNT_ID=123456
DMARCER_GEOIP_LICENSE_KEY=your_key
DMARCER_GEOIP_UPDATE_INTERVAL=24h
```

## Attribution

dmarcer is inspired by and based on [parsedmarc](https://github.com/domainaware/parsedmarc) by Domain Aware.

The following files were taken directly from the parsedmarc project:

- `assets/base_reverse_dns_map.csv` - the sender identification map (ESP/ISP/CDN reverse DNS base domains with associated names and types)

The Elasticsearch index mappings are intentionally identical to parsedmarc's so that existing Kibana dashboards remain compatible.

## License

MIT. See `LICENSE` for details.
