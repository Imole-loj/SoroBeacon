# Generic webhook

POSTs the **full structured alert as JSON** to an HTTP endpoint you control. The request is signed with HMAC-SHA256 so your receiver can authenticate deliveries.

## Setup

The following command prompts for the endpoint URL and signing secret without displaying them. The generated configuration JSON is piped directly to the API; the API does not return channel configuration.

```sh
read -r -s -p 'Receiver URL: ' WEBHOOK_URL
printf '\n'
read -r -s -p 'Webhook signing secret: ' WEBHOOK_SECRET
printf '\n'
WEBHOOK_URL="$WEBHOOK_URL" WEBHOOK_SECRET="$WEBHOOK_SECRET" \
	jq -n '{name:"incident-pipe",type:"webhook",config:{url:env.WEBHOOK_URL,secret:env.WEBHOOK_SECRET}}' \
	| curl -sS -X POST http://localhost:8080/api/v1/channels \
			-H 'Content-Type: application/json' --data-binary @-
unset WEBHOOK_URL WEBHOOK_SECRET
```

If SoroBeacon's API requires authentication, add `-H 'Authorization: Bearer <api-token>'` to the `curl` command. Keep API credentials separate from the webhook configuration.

## Config

| Key | Required | Description |
| --- | --- | --- |
| `url` | yes | HTTP(S) endpoint to POST alerts to. Treat it as sensitive; it may contain credentials. |
| `secret` | yes | HMAC-SHA256 signing key. Treat it as a secret. |
| `previous_secret` | no | Additional signing key used during a rotation. When set, SoroBeacon sends a second signature. See [Rotating the secret](#rotating-the-secret). |

## Headers

Every request carries three headers:

| Header | Example | Description |
| --- | --- | --- |
| `X-SoroBeacon-Timestamp` | `1700000000` | Decimal Unix seconds the signature covers. |
| `X-SoroBeacon-Signature` | `b7ae34…` | Hex HMAC-SHA256 over the canonical string under `secret`. |
| `X-SoroBeacon-Signature-Previous` | `d88c5d…` | Same signature under `previous_secret`. Sent only when `previous_secret` is set. |

## The canonical string

The signature covers the timestamp **and** the body, separated by a single `.`:

```
<X-SoroBeacon-Timestamp>.<raw request body>
```

For example, a delivery at `1700000000` with body `{"event_id":"e1"}` is signed over exactly these bytes:

```
1700000000.{"event_id":"e1"}
```

The digest is `HMAC-SHA256(secret, canonicalString)`, hex encoded. `internal/notify.Sign(secret, timestamp, body)` computes it.

The generic webhook sends structured JSON rather than the plain-text summary,
so it has no [`template`](templates.md) option. Transform the payload in your
receiver if your downstream service needs a different shape.

## Payload

The body is the JSON encoding of `notify.Alert`. The example includes every
field in the schema to show the full shape; optional fields depend on the alert
type. `payload` and `enrichment`, when present, are embedded as JSON values,
not quoted JSON strings.

```json
{
	"id": 42,
  "monitor_id": 1,
  "monitor_name": "Token treasury",
  "rule_id": 3,
  "rule_type": "value_threshold",
  "event_id": "0000015985348674617345-0000000001",
	"contract_id": "C...",
  "event_name": "transfer",
  "ledger": 3721765,
	"tx_hash": "transaction-hash",
	"payload": {"topics": ["transfer"], "value": "event data"},
	"enrichment": {"asset": "example"},
	"created_at": "2026-07-21T09:41:32Z",
	"severity": "warning",
	"digest": "2 alerts for Token treasury",
	"group_count": 2,
	"window_start": "2026-07-21T09:40:00Z",
	"window_end": "2026-07-21T09:41:00Z",
	"silence": 300000000000
}
```

| Field | JSON type | Meaning |
| --- | --- | --- |
| `id` | integer | Alert ID. |
| `monitor_id` | integer | ID of the monitor that generated the alert. |
| `monitor_name` | string | Monitor display name. |
| `rule_id` | integer | ID of the matching rule. |
| `rule_type` | string | Rule type, such as `value_threshold`. |
| `event_id` | string | Stable source-event identifier. |
| `contract_id` | string | Stellar contract address associated with the alert. |
| `event_name` | string | Event name, when available. |
| `ledger` | integer | Ledger sequence number. |
| `tx_hash` | string | Transaction hash. |
| `payload` | JSON value, optional | Original alert payload; omitted when empty. Its internal shape depends on the event/rule. |
| `enrichment` | JSON value, optional | Enrichment data attached to the alert; omitted when empty. |
| `created_at` | string | Alert creation time in RFC 3339 format. |
| `severity` | string, optional | `info`, `warning`, or `critical`; omitted when empty (empty is treated as `warning` by text channels). |
| `digest` | string, optional | Pre-rendered summary when the delivery represents a digest rather than a single event. |
| `group_count` | integer, optional | Number of alerts in the digest window. |
| `window_start` | string, optional | Start time of a digest window, in RFC 3339 format. |
| `window_end` | string, optional | End time of a digest window, in RFC 3339 format. |
| `silence` | integer, optional | Duration in nanoseconds for an absence-of-event alert; omitted when zero. |

The fields tagged `omitempty` are omitted when empty, except that Go's JSON
encoder can still serialize zero-valued `time.Time` fields as the zero time.
Digest fields are used for digest deliveries; `silence` is used for
absence-of-event alerts.

## HMAC scope and verification

HMAC signing is **already implemented** in the generic webhook notifier; it is
not out of scope or waiting for a future security change. Issue [#76](https://github.com/sorotrail/SoroBeacon/issues/76)
tracks the signing and secret-rotation work present here. The receiver must
verify the signature and timestamp before trusting or acting on a delivery.

## Verifying the signature

Recompute the HMAC over the **raw bytes you received** — re-serializing the JSON first changes key order and whitespace and breaks verification. Also reject stale timestamps: the timestamp is in the signed string precisely so a captured request cannot be replayed later.

```go
const maxSkew = 5 * time.Minute

// verify reports whether r is an authentic, fresh SoroBeacon delivery.
// Call it with the raw request body before unmarshalling the JSON.
func verify(r *http.Request, body []byte, secret, previousSecret string) bool {
	ts, err := strconv.ParseInt(r.Header.Get("X-SoroBeacon-Timestamp"), 10, 64)
	if err != nil {
		return false // missing or malformed timestamp
	}
	// Replay check: the timestamp is part of the signed string, so an old
	// signature cannot be reused with a fresh timestamp.
	if time.Since(time.Unix(ts, 0)).Abs() > maxSkew {
		return false
	}

	canonical := strconv.FormatInt(ts, 10) + "." + string(body)

	// Accept either the current or the rotating-out secret. Check all
	// candidates before returning so the comparison time doesn't reveal
	// which key matched.
	ok := false
	for _, key := range []string{secret, previousSecret} {
		if key == "" {
			continue
		}
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(canonical))
		expected := hex.EncodeToString(mac.Sum(nil))
		for _, header := range []string{
			"X-SoroBeacon-Signature",
			"X-SoroBeacon-Signature-Previous",
		} {
			if hmac.Equal([]byte(expected), []byte(r.Header.Get(header))) {
				ok = true
			}
		}
	}
	return ok
}
```

{% hint style="warning" %}
Compute the HMAC over the raw bytes you received — re-serializing the JSON first will change key order/whitespace and break verification.
{% endhint %}

### Rotating the secret

To rotate without dropping deliveries:

1. Put the **current** secret in `previous_secret` and the **new** secret in `secret`. SoroBeacon now sends both signatures.
2. Update your receiver to verify against the new key (accepting either, as above).
3. Once you are satisfied, clear `previous_secret`. Only `X-SoroBeacon-Signature` is sent from then on.

## Run a local receiver

Save this as `receiver.js` and run it with Node.js (`node receiver.js`). It
listens on port 9000, prints each received alert JSON, and returns `204` so
SoroBeacon treats the delivery as successful. Configure the webhook endpoint
to an address reachable from the SoroBeacon process; `localhost` from inside a
container refers to that container, not the host.

```js
const http = require('node:http');

const server = http.createServer((request, response) => {
	if (request.method !== 'POST') {
		response.writeHead(405).end();
		return;
	}

	const chunks = [];
	request.on('data', (chunk) => chunks.push(chunk));
	request.on('end', () => {
		try {
			const alert = JSON.parse(Buffer.concat(chunks).toString('utf8'));
			console.log(JSON.stringify(alert, null, 2));
			response.writeHead(204).end();
		} catch {
			response.writeHead(400).end();
		}
	});
});

server.listen(9000, '0.0.0.0', () => {
	console.log('Webhook receiver listening on port 9000');
});
```

This capture-only example does not verify HMAC. Do not expose it as a
production receiver; use the verification procedure above before processing
real deliveries.

## Delivery semantics

Any HTTP status from `200` through `299` is success. The response body for a
successful response is drained and discarded. A non-2xx response is a failed
delivery and may be retried according to the dispatcher policy. For a non-2xx
response, SoroBeacon reads at most the first 300 response-body bytes; the
sanitized failure text can be stored in the delivery attempt's
`response_snippet` (capped at 500 bytes) and is visible to operators. Keep
response bodies short and never include credentials, webhook URLs, or other
secrets in them. Make your receiver idempotent on `event_id` and `rule_id` so
retries do not duplicate downstream work.
