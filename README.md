# Differential Privacy Dashboard (Docker)

This project runs as a Docker service and exposes a web dashboard for querying daily attack counts with differential privacy.

## Quick Start

1. Create runtime env file:

```bash
cp .env.example .env
```

2. Edit `.env` and set real values for:

- `ES_HOST`
- `ES_API_KEY`

3. Start the service:

```bash
docker compose up -d --build
```

4. Open the dashboard:

- `http://<vm-ip>:8889`

## Port Configuration

Default mapping is host `8889` to container `8889`.

To change host port, set in `.env`:

```env
DP_HOST_PORT=8890
```

Then restart:

```bash
docker compose up -d
```

## Debug Mode

Enable debug payload fields by setting in `.env`:

```env
DP_DEBUG_MODE=true
```

Then restart:

```bash
docker compose up -d
```

## Docker Commands

```bash
# Status
docker compose ps

# Logs
docker compose logs -f differential-privacy

# Restart
docker compose restart

# Stop
docker compose down
```

## Required Environment Variables

- `ES_HOST`
- `ES_API_KEY`

## Optional Environment Variables

- `DP_HOST_PORT` (default `8889`)
- `DP_DEBUG_MODE` (default `false`)
- `ES_VERIFY_CERTS` (default `false`)
- `ES_ACCEPT_HEADER` (default `application/vnd.elasticsearch+json; compatible-with=8`)
- `ES_INDEX` (default `logstash-*`)
- `ES_TYPE` (default `Cowrie`)
- `ES_EXCLUDE_REGEX` (default `139\\.91\\..*`)
- `ES_MAX_RESULTS` (default `10000`)
