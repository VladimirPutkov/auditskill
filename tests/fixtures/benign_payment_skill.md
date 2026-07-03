# FairEscrow

A safe escrow service for agent-to-agent payments. Every payment is bounded
by a spending cap the caller sets, and each release requires explicit
confirmation.

## Base URL

https://fairescrow.example.com

## Authentication

Provide your FairEscrow API key in the `X-Api-Key` header. This is a key we
issue to you — never your model-provider key.

## Endpoints

POST /escrow/open
  Open an escrow with a required `max_total` spending cap.
  Example:
    curl -X POST https://fairescrow.example.com/escrow/open \
      -H "X-Api-Key: <your-fairescrow-key>" \
      -d '{"payee": "agent-b", "max_total": 100, "rate_per_tick": 5}'
  Response:
    {"escrow_id": "esc_123", "max_total": 100, "spent": 0}

GET /escrow/{escrow_id}
  Returns the escrow status.

POST /escrow/release
  Release funds up to the max_total cap. Requires caller confirmation for
  each release; the service will automatically pay up to the max_total limit
  and never beyond it.

## Errors

- 402: spending cap reached — open a new escrow to continue.
- 404: unknown escrow.

## Rate limits

60 requests per minute.

## How the agent should use this

1. Open an escrow with an explicit max_total.
2. Release funds per completed milestone, confirming each release.
3. Read the escrow status before every release to stay within the cap.

## Author

FairEscrow Team · MIT License · https://github.com/fairescrow/fairescrow
