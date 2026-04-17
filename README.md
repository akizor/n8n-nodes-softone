# n8n SoftOne Node

Custom n8n node for the [SoftOne](https://www.softone.gr/) ERP JSON API. Exposes the core SoftOne services — `login`/`authenticate`, `SqlData`, `getData`/`getBrowserInfo`/`setData`, plus a generic form-POST for custom server-side job endpoints — so n8n workflows can read and write SoftOne directly.

## Features

- **Transparent authentication.** Every operation logs in and authenticates on first use, reuses the session across all subsequent items in the same execution, and never exposes the session token as workflow output.
- **SQL Data.** Run any named SoftOne SQL (`Tari`, `Judete`, `Monede`, `scadentec`, `findfindoc`, `finditems`, …) with a preset dropdown plus `param1/2/3`, or any custom SqlName.
- **Object.** `Get by Key` (getData), `List` (getBrowserInfo), `Create` and `Update` (setData) against any SoftOne OBJECT (`CUSTOMER`, `ITEM`, `MTRCATEGORY`, `MTRMANFCTR`, `FINDOC`, `MTRDOC`, `PRSN`, …).
- **Custom Endpoint.** Generic `POST Form` against any server-side job endpoint configured on your SoftOne instance. The authenticated `clientID` is auto-injected so it never lands in workflow JSON.
- **Credential verification.** The "Test" button in the credentials UI performs a full login + authenticate round-trip and reports the exact failure reason.

## Installation

1. Copy this repository into your n8n custom nodes directory (typically `~/.n8n/custom/nodes/`).
2. Install dependencies:
   ```sh
   npm install
   ```
3. Build:
   ```sh
   npm run build
   ```
4. Restart n8n.

## Credentials

Create a **SoftOne API** credential with:

| Field | Description |
|---|---|
| Host | Full SoftOne base URL (`https://sXXXX.softone.gr`). HTTPS is required unless "Allow Unsafe Host" is enabled. |
| Username | SoftOne login username. |
| Password | SoftOne login password. |
| App ID | SoftOne application identifier. |
| Company ID | Optional. SoftOne `COMPANY` code used during `authenticate`. Leave empty for the first accessible company. |
| Login Date | Optional. `YYYY-12-31` to log into a specific fiscal year. |
| Allow Unsafe Host | Disabled by default. Enables non-HTTPS / private / loopback / link-local / metadata hosts — only for trusted development endpoints. |

### Multiple companies or fiscal years

One credential authenticates into exactly one `COMPANY` + fiscal-year scope. To work with another company or year, create a separate credential and attach it to the node that needs it.

### Test button

Click **Test** on a credential to perform a full login + authenticate round-trip. A failure message reports whether login, company selection, or authenticate failed.

## Operations

### SQL Data

**Run Named SQL** invokes the SoftOne `SqlData` service with a `SqlName` (preset or custom) and optional `param1`, `param2`, `param3`. Enable **Split Rows** (default on) to emit one n8n item per row in `rows[]`; disable to get the full response as a single item.

### Object

- **Get by Key** — `getData` service, returns one object by its primary key.
- **List** — `getBrowserInfo` service with `FILTERS` / `START` / `LIMIT`.
- **Create** — `setData` with a JSON `data` body.
- **Update** — `setData` with a `KEY` and JSON `data` body.

### Custom Endpoint

**POST Form** sends a URL-encoded form body to any `${host}${endpointPath}` on the SoftOne instance (e.g., a SoftOne Job Scheduler script that generates a PDF, cancels a document, or exposes any other custom operation). Useful when a SoftOne installation exposes tenant-specific endpoints beyond the standard JSON API.

- **Endpoint Path** — required, absolute (`/...`), no query strings, no `..` segments, restricted character set.
- **Form Data** — URL-encoded body. Do not include `clientID` — the node injects it from the authenticated session.
- **Response Type** — Binary (returns an n8n binary property with sanitized file name and MIME type) or Text (returns the raw response body as a string).

## Example

```
[Schedule] → [SoftOne: SQL Data → Run Named SQL → scadentec] → [Filter] → [Sheets]
```

```
[Webhook] → [SoftOne: Object → Create → CUSTOMER] → [Reply 201]
```

## Security

The node enforces HTTPS (with an opt-in escape hatch), blocks RFC1918 / loopback / link-local / metadata addresses, strips prototype-pollution keys from user JSON, sanitizes file names, and redacts credentials and session tokens before errors reach the execution log. The full security posture is:

- Password is never echoed in outputs; `clientID` is auto-injected into Custom Endpoint calls server-side and never handled in workflow params.
- Failed SoftOne responses pass through a secret-redactor before becoming `NodeApiError` payloads.
- HTTP redirects are disabled on every call to prevent credential forwarding via a malicious 3xx.
- TLS certificate validation cannot be silently disabled by host environment overrides.

## Development

- Sources: `src/SoftOne.node.ts`, `src/SoftOneApi.credentials.ts`
- Build output: `nodes/*`
- Icon: `src/softOne.svg` (copied into `nodes/` on build)

## License

MIT — see [LICENSE](./LICENSE).
