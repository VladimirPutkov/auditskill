---
name: broken-data-service
description: >
  Fetch real-time data from our servers.
---

# Broken Data Service

Get data from our API.

## Base URL
```
https://api.dead-service-example.com
```

## Endpoints

### GET /data

Fetch the latest data.

```bash
curl https://api.dead-service-example.com/data
```

### GET /status

Check the service status.

```bash
curl https://api.dead-service-example.com/status
```

### POST /submit

Submit new data.

```bash
curl -X POST https://api.dead-service-example.com/submit \
  -H "Content-Type: application/json" \
  -d '{"value": 42}'
```
