# xfcc

A strict, fail-closed parser for Envoy's [`x-forwarded-client-cert`][xfcc] (XFCC) header, for Node.js. It is pure TypeScript with no runtime dependencies.

It is built for authorization paths. Anything that deviates from the format rejects the whole header, and parsing is a single linear pass with hard size limits.

## Installation

```sh
pnpm add xfcc-parser
```

Node.js >= 22.18.

## Usage

```ts
import { parseDistinguishedName, parseXfcc, XfccError } from 'xfcc-parser';

// `format` is required: match it to the Envoy listener. maxElements defaults
// to 1; set it to the exact number of proxy hops, so a SAN cannot smuggle in an
// extra element.
const elements = parseXfcc(request.headers['x-forwarded-client-cert'], {
  format: 'json',
  maxElements: 1,
});

// The LAST element was appended by the proxy closest to this service. Require
// exactly one URI SAN: in the text format, two SANs and one crafted SAN can
// look the same.
const nearest = elements.at(-1);
if (nearest?.uri.length !== 1 || nearest.uri[0] !== 'spiffe://cluster.local/ns/payments/sa/api') {
  throw new Forbidden();
}
```

```ts
parseXfcc(
  'By=http://frontend.lyft.com;Hash=468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688;Subject="CN=Test Client,OU=Lyft,L=San Francisco,ST=CA,C=US";URI=http://testclient.lyft.com',
  { format: 'text' },
);
// [
//   {
//     by: ['http://frontend.lyft.com'],
//     hash: '468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688',
//     cert: null,
//     presentedChain: [],
//     subject: 'CN=Test Client,OU=Lyft,L=San Francisco,ST=CA,C=US',
//     uri: ['http://testclient.lyft.com'],
//     dns: [],
//     issuer: null,
//   },
// ]

parseDistinguishedName('CN=evil\\,O=Admin,O=Lyft');
// [
//   [{ type: 'CN', value: 'evil,O=Admin', encoding: 'string' }],
//   [{ type: 'O', value: 'Lyft', encoding: 'string' }],
// ]
```

### `parseXfcc(header, options)`

Parses a header value and returns a deeply frozen array of elements in header order.

- `header`: `string | readonly string[] | undefined`. `undefined` (no header) returns `[]`. An array (the header sent more than once) is joined with `,`, as [RFC 9110][rfc9110] specifies.
- `options.maxLength`: the maximum length in bytes. Defaults to `65536`, up to `1048576`. It is checked before anything else.
- `options.format` (required): `'text'` or `'json'`. Set it to match the Envoy listener's [`set_current_client_cert_details.format`][set-current]. The format is never detected from the value, because a text header can be crafted to look like JSON: the leading `[` can come from a client-forwarded prefix and the trailing `]` from a URI SAN.
- `options.maxElements`: the maximum number of elements (proxy hops). Defaults to `1`, up to `1024`. If more than one of your proxies appends an element, set it to the exact hop count: in the text format, a crafted SAN can add a forged last element.

`options` must be a plain object (from any realm, or with a `null` prototype) with `format` set. An unknown key, such as a misspelt `maxElement`, throws `TypeError` rather than being ignored, and so does a non-enumerable or symbol key. A polluted `Object.prototype` cannot change a default, and any other prototype, such as a class instance, throws `TypeError` rather than having its inherited options ignored.

| Field            | Type                | Notes                                                                                                                                                             |
| ---------------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `by`             | `readonly string[]` | URI SANs of the proxy's certificate. Each is an [RFC 3986][rfc3986] URI.                                                                                          |
| `hash`           | `string \| null`    | 64 lowercase hex characters.                                                                                                                                      |
| `cert`           | `string \| null`    | Percent-decoded PEM, checked against [RFC 7468][rfc7468] (see below).                                                                                             |
| `presentedChain` | `readonly string[]` | One PEM per certificate, leaf first, as the client presented it. **This is not the validated chain.**                                                             |
| `subject`        | `string \| null`    | An [RFC 4514][rfc4514] string, exactly as Envoy sent it, escapes included. Use `parseDistinguishedName` to read it.                                               |
| `uri`            | `readonly string[]` | URI SANs of the client certificate. Each is an RFC 3986 URI.                                                                                                      |
| `dns`            | `readonly string[]` | DNS SANs of the client certificate. A wildcard is allowed only as the whole leftmost label.                                                                       |
| `issuer`         | `string \| null`    | An RFC 4514 string. Envoy sends `Issuer` from 1.40. Always `null` in the text format (see [Security / trust model](#security--trust-model)); use JSON to read it. |

### `getPeerSpiffeId(header, options)`

Returns the SPIFFE ID of the mTLS peer that connected to the proxy closest to this service: the last element of the header. It takes the same arguments as `parseXfcc`, plus `options.requireSingleSan`. If more than one of your proxies appends an element, set `maxElements` to the exact hop count.

```ts
import { getPeerSpiffeId } from 'xfcc-parser';

const peer = getPeerSpiffeId(request.headers['x-forwarded-client-cert'], { format: 'json' });
// {
//   id: 'spiffe://cluster.local/ns/payments/sa/api',
//   trustDomain: 'cluster.local',
//   path: '/ns/payments/sa/api',
//   namespace: 'payments',
//   serviceAccount: 'api',
// }
```

`namespace` and `serviceAccount` are set only when the path is exactly `/ns/<namespace>/sa/<account>`, the Istio layout. For any other mesh, read `path`.

It throws `XfccError` with a `code` of `NO_PEER`, `NOT_ONE_URI`, `NOT_ONE_SAN`, `NOT_SPIFFE` or `INVALID_SPIFFE_ID` (and no `offset`) if the header has no element, the last element does not have exactly one URI SAN, has any DNS SAN (unless `requireSingleSan` is `false`), or that SAN is not a valid workload SPIFFE ID. A malformed header throws `XfccError` with the header's own code. The ID must follow the [SPIFFE-ID standard][spiffe-id] and be at most 2048 bytes, with a trust domain of at most 255 bytes. The scheme must be lowercase, which is stricter than the standard.

It cannot tell whether a crafted SAN forged the last element (see [Security / trust model](#security--trust-model)), so it is only as safe as the `maxElements` you pass. It does not check `issuer`. `options.requireSingleSan` defaults to `true`, so an element with any DNS SAN is rejected with `NOT_ONE_SAN`: in the text format a URI SAN `spiffe://td/a;DNS=b` is byte-for-byte a certificate with both SANs. Set it to `false` only if your workload certificates also carry DNS SANs. With `false`, that crafted SAN returns `spiffe://td/a`. Unless a crafted SAN forged the element, that is always the part before the first `;` of a SAN your CA signed, so it matters only for a CA that signs URI SANs without checking the SPIFFE ID syntax; behind such a CA, use the JSON format. If a proxy that is not the caller sits between the caller and this service, this returns that proxy's ID. Match the result against an allow list with exact comparisons, on `id` or on `trustDomain` as well as `namespace` and `serviceAccount`.

### `parseDistinguishedName(dn)`

Parses an RFC 4514 distinguished name into RDNs, in string order. That is the most specific RDN first, the reverse of ASN.1 order. Escapes are decoded and multi-valued RDNs (`+`) are kept together. A `#hex` value is returned as lowercase hex with `encoding: 'hex'`. A decoded value can hold any character the certificate does, including control and bidi characters: Envoy writes a tab as `\09`, and this returns it as a raw tab. Escape values before you log or display them. Input longer than 1 MiB (the `maxLength` ceiling) is rejected with `TOO_LONG`. A string with a lone surrogate is rejected with `INVALID_DN`.

### Errors

Every function throws `XfccError`, which has a stable `code` and the byte `offset` where the problem was found (`getPeerSpiffeId`'s own codes have none). For `INVALID_JSON`, that is the first offending byte; for an invalid JSON value, the value's opening quote or bracket; for an element-level error such as `MISSING_HASH`, the start of the element; for `TOO_LONG`, the limit, which is the first byte past it. A surplus JSON element reports `TOO_MANY_ELEMENTS` without being validated. Messages never include the input, so they are safe to log. An `XfccError` has no stack trace: capturing one dominates the cost of rejecting a header, and it says nothing about untrusted input. Codes:

`EMPTY`, `TOO_LONG`, `TOO_MANY_ELEMENTS`, `INVALID_CHAR`, `EMPTY_ELEMENT`, `EMPTY_PAIR`, `MISSING_EQUALS`, `UNKNOWN_KEY`, `DUPLICATE_KEY`, `EMPTY_VALUE`, `UNTERMINATED_QUOTE`, `UNEXPECTED_AFTER_VALUE`, `INVALID_QUOTING`, `INVALID_ESCAPE`, `INVALID_HASH`, `INVALID_URI`, `INVALID_DNS`, `INVALID_PERCENT_ENCODING`, `INVALID_PEM`, `INVALID_DN`, `KEY_ORDER`, `MISSING_HASH`, `INVALID_JSON`, `NO_PEER`, `NOT_ONE_URI`, `NOT_ONE_SAN`, `NOT_SPIFFE`, `INVALID_SPIFFE_ID`.

A wrong argument type or an invalid option throws `TypeError`, not `XfccError`: it is a bug in the caller, not a rejected header.

## Security / trust model

XFCC is only as trustworthy as the proxies that set it. Check all of the following:

- **Strip the header at the edge.** The first proxy must use [`forward_client_cert_details`][forward-details]`: SANITIZE_SET`, or `SANITIZE` when it does no mTLS. Otherwise a client can send its own XFCC.
- **Trust only elements your proxies added.** With `APPEND_FORWARD`, each hop appends an element, so the last element comes from the nearest proxy. Earlier elements are only as trustworthy as the hops that forwarded them.
- **Make sure only your proxy can reach the service**, for example with mTLS between proxy and service or network policy. If the service can be reached directly, anyone can set the header.
- **Do not authorize on `presentedChain`.** Envoy forwards the chain the client presented, not the chain it validated.
- **Prefer the JSON format** (`set_current_client_cert_details.format: JSON`, Envoy 1.38 and later), and pass `format: 'json'`. In the text format Envoy writes `By`, `URI` and `DNS` values unescaped, and `,`, `;` and `=` are legal in a URI. So a CA that will sign a crafted SAN lets its holder add identities:
  - A URI SAN `spiffe://td/x;URI=spiffe://td/admin` is byte-for-byte the same as two URI SANs, and a DNS SAN `a.com;DNS=admin.internal` the same as two DNS SANs. A URI SAN `https://x.example/;DNS=admin.internal` is the same as a URI SAN plus a DNS SAN, and `…;Issuer="CN=Trusted CA"` is the same as a real `Issuer`. No parser can tell these apart, so require exactly one SAN across `uri` and `dns` combined (`getPeerSpiffeId` does this by default). For the same reason `issuer` is always `null` in the text format: `Issuer` is still parsed and validated, but never returned.
  - A URI SAN `https://x.example/a,By=…;Hash=…;URI=spiffe://td/admin` adds a forged last element. `maxElements` defaults to `1`; if you raise it, set it to the exact hop count.
  - SPIFFE IDs cannot contain `;` or `,`, so a CA that enforces the SPIFFE ID syntax (such as SPIRE) never issues these SANs as SPIFFE IDs. It may still issue them in a non-SPIFFE URI SAN, such as the `https:` one above.
- **In the JSON format, keep `SANITIZE_SET` at the edge.** With `APPEND_FORWARD`, Envoy appends in the text format when the incoming header is not a bracketed JSON array. A client-forwarded prefix plus a crafted SAN can then wrap Envoy's text in a JSON string. The parser rejects any `by` or `uri` value containing `Hash=` for this reason.
- **Match on parsed values.** Compare `uri`/`dns` entries exactly, and read DN attributes with `parseDistinguishedName`. Never use substring or regex matches on `subject`.

What the parser enforces, in addition to the format grammar:

- **Keys and quoting:** only the eight keys Envoy defines (case-insensitive). `Hash`, `Cert`, `Chain`, `Subject` and `Issuer` may appear at most once per element. In the text format, quoting must match Envoy's: `Cert`, `Chain`, `Subject` and `Issuer` are always quoted, and `By`, `Hash`, `URI` and `DNS` never are. Also in the text format, keys must appear in the order Envoy writes them (`By`, `Hash`, `Cert`, `Chain`, `Subject`, `URI`, `DNS`, `Issuer`; `By`, `URI` and `DNS` may repeat), and every element must have a `Hash`. Together these reject a SAN that reorders keys, starts an element without a `Hash` or writes a `Cert`. They cannot reject the cases listed under "Prefer the JSON format" above. A JSON element may omit `hash`, because Envoy JSON-escapes SANs, so a SAN cannot add a JSON element.
- **Characters:** only visible ASCII, SP and HTAB are accepted. Control characters, `obs-text` and non-ASCII are rejected. `Subject` and `Issuer` also reject a raw tab, and in JSON any control or non-ASCII character (Envoy JSON-escapes control characters, and escapes every non-ASCII byte in a DN as `\XX`), so the `subject` and `issuer` strings cannot reach logs unescaped. Values decoded by `parseDistinguishedName` can.
- **Value validation:** URIs must be RFC 3986 URIs with the non-empty scheme-specific-part RFC 5280 requires, so `urn:` is rejected. In the JSON format, a `by` or `uri` value containing `Hash=` is rejected with `INVALID_URI`. DNS names must be LDH hostnames ([RFC 1034][rfc1034], [RFC 1123][rfc1123], [RFC 5280][rfc5280]) whose last label is not all-numeric, so `1.2.3.4` is rejected. Hashes must be 64 lowercase hex characters. `Cert`/`Chain` use Envoy's percent-encoding (`+` is never treated as a space), followed by RFC 7468 PEM, canonical base64 and a DER framing check. The body must follow the strict grammar (64-character lines, then one shorter line), but trailing whitespace after the `BEGIN`/`END` lines and a missing final line break are accepted, as RFC 7468 parsers should.
- **DN escapes:** RFC 4514 escapes inside `Subject`/`Issuer` are kept exactly as sent, so `CN=a\,O=Admin` can never be read as two RDNs.
- **JSON:** each element must be a non-empty object. Unknown, duplicate and escaped keys (`"h\u0061sh"`), lone surrogates, `null`, empty strings and empty arrays are all rejected.

Deliberate deviations and limits:

- **Quoting in the text format:** Envoy's docs say a value containing `,`, `;` or `=` should be quoted, with `"` written as `\"`. Envoy's code does neither, and this parser follows the code: `By`, `Hash`, `URI` and `DNS` must be unquoted, and a quoted value's backslash escapes are not decoded, because the `\"` in a real `Subject` is an RFC 4514 escape. A producer that follows Envoy's docs rather than its code can be rejected. Accepting both would let a crafted SAN pick either form.
- **Empty elements:** [RFC 9110][rfc9110-lists] says recipients of a comma-separated list must ignore empty elements. Envoy never writes them, so `a,,b` and a trailing comma are rejected with `EMPTY_ELEMENT`.
- **DN separators:** the obsolete [RFC 2253][rfc2253] `;` separator is rejected.
- **NUL:** a DN value that decodes to U+0000 is rejected.
- **`Hash` is not compared with `Cert`:** Envoy always writes them consistently, and anyone who can forge an element (see above) can include any public certificate with its correct hash, so a match would prove nothing.
- **Certificate contents:** X.509 contents are not parsed. If you need more than the fields above, pass `cert` to `node:crypto`'s `X509Certificate`.
- **Envoy's documentation example:** the second JSON example in Envoy's docs abbreviates the SHA-256 digests to 32 hex characters, and this parser rejects it. Real Envoy output always has 64.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

### Verifying a release

Every release is published from GitHub Actions with [npm trusted publishing][npm-trusted] and provenance:

```sh
npm audit signatures
```

The package has no dependencies and no install scripts, and a test fails if it gains either.

## Development

pnpm is the only tool you need. `devEngines` in `package.json` pins pnpm and Node, and `pnpm-lock.yaml` locks both with checksums, so `pnpm install` downloads the right Node into the project and scripts run on it:

```sh
pnpm install --frozen-lockfile

pnpm build
pnpm test
pnpm fuzz parse -max_total_time=60   # also: dn, options, cert
```

Tests include property tests ([fast-check][fast-check]) on every run, and `test/fixtures/golden.json`, a set of recorded inputs and results that pins the parser's behaviour.

Fuzzing is coverage-guided, with [Jazzer.js][jazzer], and runs locally. `fuzz/` is its own pnpm workspace, so the fuzzer's dependencies stay out of the main install.

[OpenSSF Scorecard][scorecard] grades the repository's security practices on every push to `main` and weekly.

pnpm and Renovate both wait 7 days before taking a new release. pnpm also blocks install scripts, exotic subdependencies and packages that lose their publishing trust level.

To refresh the test certificates, run `scripts/gen-fixtures.sh`.

### Benchmarking

```sh
pnpm bench
```

This builds the package and benchmarks `dist/`, because Vitest's module runner adds overhead to anything imported from `src/`. `bench/results.md` holds the latest recorded numbers. The 1 MiB cases in `bench/cases.ts` are the worst inputs the size limits allow, and catch anything that is not linear in the input.

### Releasing

1. Add a changeset with `pnpm changeset`. Merging to `main` opens a "Version Packages" PR.
2. Merging that PR builds and tests the package, then stages it on npm after approval in the `release` environment.
3. Review the staged version with `npm stage view <id>`, then approve it with 2FA using `npm stage approve <id>` or on npmjs.com.
4. Create the GitHub release and tag with `scripts/release.sh [version]`. It tags the commit named in the npm provenance and uses the version's section of `CHANGELOG.md` as the notes.

## License

[MIT](LICENSE)

[xfcc]: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
[fast-check]: https://fast-check.dev/
[forward-details]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto#envoy-v3-api-field-extensions-filters-network-http-connection-manager-v3-httpconnectionmanager-forward-client-cert-details
[jazzer]: https://github.com/CodeIntelligenceTesting/jazzer.js
[npm-trusted]: https://docs.npmjs.com/trusted-publishers
[rfc1034]: https://www.rfc-editor.org/rfc/rfc1034.html
[rfc1123]: https://www.rfc-editor.org/rfc/rfc1123.html
[rfc2253]: https://www.rfc-editor.org/rfc/rfc2253.html
[rfc3986]: https://www.rfc-editor.org/rfc/rfc3986.html
[rfc4514]: https://www.rfc-editor.org/rfc/rfc4514.html
[rfc5280]: https://www.rfc-editor.org/rfc/rfc5280.html
[rfc7468]: https://www.rfc-editor.org/rfc/rfc7468.html
[rfc9110]: https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3
[rfc9110-lists]: https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1
[scorecard]: https://scorecard.dev/
[set-current]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto#envoy-v3-api-field-extensions-filters-network-http-connection-manager-v3-httpconnectionmanager-set-current-client-cert-details
[spiffe-id]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
