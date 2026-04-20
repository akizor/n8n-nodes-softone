# n8n SoftOne Node

Custom n8n node for the [SoftOne](https://www.softone.gr/) ERP JSON API. Wraps every documented service — authentication, SQL queries, business-object CRUD, browser pagination, calculation, metadata discovery, reports, and custom job endpoints — so n8n workflows can read and write SoftOne directly, with secure session handling and strong defaults.

## Features

- **Transparent authentication.** Every operation logs in and authenticates on first use, reuses the session across all subsequent items in the same execution, and never exposes the session token as workflow output.
- **SQL Data.** Run any named SoftOne SQL query (preset dropdown or custom name) with up to three params.
- **Object CRUD.** Get by key, list with paginated browsers, create, update, delete, and dry-run-calculate against any SoftOne OBJECT.
- **Filter builder.** Compose `getBrowserInfo` FILTERS field-by-field (Equals, Contains, Starts/Ends With, Range, In List, Is True/False), or fall back to a raw FILTERS string.
- **Auto-pagination.** `List` with **Fetch All** loops `getBrowserData` for you up to a configurable row cap.
- **Row normalization.** `getBrowserInfo` returns rows as positional arrays; the node zips them with `fields[]` so you get `{FIELD: value}` objects matching `SqlData` output.
- **Metadata discovery.** Live introspection — list every Business Object, drill into its tables, list each table's fields with type and required flags. No build-time schema extractor needed.
- **Reports.** Run a SoftOne report and fetch its HTML pages — single page, all pages concatenated, or one item per page.
- **Custom Endpoint.** Generic form-POST against any server-side job endpoint configured on your SoftOne instance, with the authenticated `clientID` auto-injected.
- **Credential verification.** The "Test" button in the credentials UI performs a full login + authenticate round-trip and reports the exact failure reason mapped to SoftOne's documented error codes.

## Installation

1. Settings → Community Nodes → Install → `n8n-nodes-softone`. Requires `N8N_COMMUNITY_PACKAGES_ENABLED=true` on the n8n server (default in n8n ≥ 1.0).
2. Or install manually: copy this repo into `~/.n8n/custom/`, run `npm install && npm run build`, and restart n8n.

## Credentials

Create a **SoftOne API** credential with:

| Field | Description |
|---|---|
| Host | Full SoftOne base URL (`https://sXXXX.softone.gr`). HTTPS is required unless **Allow Unsafe Host** is enabled. |
| Username | SoftOne login username. |
| Password | SoftOne login password. |
| App ID | SoftOne application identifier. |
| Company ID | Optional. SoftOne `COMPANY` code used during `authenticate`. Leave empty for the first accessible company. |
| Login Date | Optional. `YYYY-12-31` to log into a specific fiscal year. |
| Allow Unsafe Host | Disabled by default. Enables non-HTTPS / private / loopback / link-local / metadata hosts — only for trusted development endpoints. |

### Multiple companies or fiscal years

One credential authenticates into exactly one `COMPANY` + fiscal-year scope. To work with another company or year, create a separate credential and attach it to the node that needs it.

### Test button

Click **Test** on the credential to perform a full login + authenticate round-trip. Failure messages identify which step failed (host validation, login, company selection, authenticate) and surface SoftOne's documented error codes (e.g. `-2: Authenticate failed — invalid credentials`, `-101: Session expired`).

## Operations

### SQL Data

**Run Named SQL** invokes the `SqlData` service with a `SqlName` (from the preset list or custom) and optional `param1` / `param2` / `param3`. Enable **Split Rows** (default on) to emit one item per row in `rows[]`; disable to get the full response as a single item.

### Object

| Operation | SoftOne service | Notes |
|---|---|---|
| Get by Key | `getData` | Optional `LOCATEINFO` to limit returned fields, optional `FORM`. |
| List | `getBrowserInfo` | Builder or raw FILTERS, configurable `LIMIT`, optional `FORM`. With **Fetch All** auto-paginates via `getBrowserData` up to **Max Rows** (default 10000). With **Split Rows** off, output includes `reqID`/`totalcount`/`fields`/`columns`. |
| List Next Page | `getBrowserData` | Manual pagination — pass the `reqID` from a previous List call plus `START` / `LIMIT`. |
| Create | `setData` | Optional **Return Saved Data** (sends `VERSION: 2`) plus optional `LOCATEINFO` for narrowed payload. |
| Update | `setData` | Same as Create plus required `KEY`. |
| Delete | `delData` | Removes a record by `OBJECT` + `KEY`. |
| Calculate | `calculate` | Dry-run `setData` — returns computed values without persisting. Use to validate payloads or preview server-side calculations. |

#### Filter builder

`List` exposes a **Filter Mode** toggle (Builder / Raw). In Builder mode each row is a `TABLE.FIELD` plus an operator:

| Operator | Compiles to | Notes |
|---|---|---|
| Equals | `FIELD=value` | Exact match |
| Contains | `FIELD=%value%` | LIKE |
| Starts With | `FIELD=value%` | LIKE |
| Ends With | `FIELD=%value` | LIKE |
| Range (Between) | `FIELD=from...to` | Three-dot S1 range |
| In List (OR) | `FIELD=v1\|v2\|v3` | Pipe-separated values inside one field |
| Is True / Is False | `FIELD=1` / `FIELD=0` | Boolean flags |

Rows are AND-joined with `&`. Literal `&`, `=`, `|` inside values are URL-encoded automatically so they can't break the FILTERS grammar. Switch to Raw mode for grammars the builder doesn't cover.

### Metadata

Live SoftOne schema discovery — useful for figuring out what to send to `setData` without leaving n8n.

| Operation | SoftOne service | Returns |
|---|---|---|
| List Objects | `getObjects` | Every Business Object on the tenant with name/type/caption. |
| List Object Tables | `getObjectTables` | Tables that make up an Object (e.g. `CUSTOMER` → `CUSTOMER`, `CUSEXTRA`, …). |
| List Table Fields | `getTableFields` | Fields of one table — name, type, size, required, readOnly, defaults. |
| Get Form Design | `getFormDesign` | Tables + fields with full presentation metadata. |
| Get Dialog | `getDialog` | Browser/dialog fields with presentation metadata. |
| Selector Lookup | `getSelectorData` | Filtered editor lookups (e.g. customers matching `30*`). |
| Fields by Key | `selectorFields` | Pull named fields for a record by primary key. |

A common discovery flow: `List Objects` → pick `CUSTOMER` → `List Object Tables → CUSTOMER` → `List Table Fields → CUSEXTRA` → now you know exactly what JSON shape to feed `Object → Create`.

### Report

**Run Report** wraps `getReportInfo` + `getReportData`:

- **Fetch All Pages** (default on) loops every page returned by `npages`; **Split Pages** controls whether each page becomes its own n8n item or all pages are concatenated into one HTML blob.
- Off → fetches just the **Page Number** you specify.
- Output: `{reqID, pageNum, npages, html}`.

### Custom Endpoint

**POST Form** sends a URL-encoded body to `${host}${endpointPath}` for any server-side job endpoint configured on your SoftOne instance (PDF generators, document cancellers, custom integrations).

- **Endpoint Path** — required, absolute (`/…`), no query strings, no `..` segments, restricted character set.
- **Form Data** — URL-encoded body. Do not include `clientID` — the node injects it from the authenticated session.
- **Response Type** — Binary (n8n binary property with sanitized file name and MIME type) or Text (raw response body string).

## Examples

```
[Schedule] → [SoftOne: SQL Data → Run Named SQL → scadentec] → [Filter] → [Google Sheets]
```

```
[Webhook] → [SoftOne: Object → Create → CUSTOMER (Return Saved Data)] → [Reply 201]
```

```
[Trigger] → [SoftOne: Metadata → List Table Fields (CUSTOMER, CUSTOMER)]
         → use the field list to compose a Create payload programmatically
```

```
[Cron] → [SoftOne: Object → List → ITEM (Fetch All, Filter: MTRL.SODTYPE Equals 51)]
       → [HTTP Request: push to downstream system]
```

## Error handling

SoftOne's documented error codes are mapped to readable hints. A typical failure looks like:

```
SoftOne API error: Authenticate fails due to invalid credentials. [-2: Authenticate failed — invalid credentials.]
```

Codes covered include session expirations (`-101`, `-100`, `-7`), licence/AppId errors (`-11`, `-6`, `-5`, `-4`), authentication failures (`-2`, `-1`, `1001`), business errors (`2001` Data does not exist), and internal errors (`11`, `99`).

When **Continue On Fail** is enabled, the failing item emits `{error: "..."}` with the message above instead of stopping the workflow. SoftOne response payloads are passed through a secret redactor before becoming error data — passwords, usernames, `clientID`, and `appid` are stripped.

## Security

The node enforces HTTPS (with an opt-in escape hatch), blocks RFC1918 / loopback / link-local / metadata addresses, strips prototype-pollution keys from user JSON, sanitizes file names, and redacts credentials and session tokens before errors reach the execution log. The full security posture:

- Password is never echoed in outputs; `clientID` is auto-injected into Custom Endpoint calls server-side and never handled in workflow params.
- Auth operations never expose the session token as item data.
- Failed SoftOne responses pass through a secret-redactor before becoming `NodeApiError` payloads.
- HTTP redirects are disabled on every call to prevent credential forwarding via a malicious 3xx.
- TLS certificate validation cannot be silently disabled by host environment overrides.
- User-supplied JSON is recursively scrubbed of `__proto__` / `constructor` / `prototype` keys.
- File names from binary outputs are sanitized against path traversal.

## Development

- Sources: `src/SoftOne.node.ts`, `src/SoftOneApi.credentials.ts`
- Build output: `nodes/*`
- Icon: `src/softOne.svg` (copied into `nodes/` on build)
- Build: `npm run build`
- Watch: `npm run dev`

## License

MIT — see [LICENSE](./LICENSE).
