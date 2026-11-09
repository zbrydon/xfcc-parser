# xfcc-parser

## 0.1.0

### Minor Changes

- Initial release ([`170db1d`](https://github.com/zbrydon/xfcc-parser/commit/170db1d3ce8c519e5d110a458bd53ef6b7129940))

  Strict, fail-closed parser for Envoy's `x-forwarded-client-cert` header (text and JSON formats) with an RFC 4514 distinguished name parser. Pure TypeScript with no runtime dependencies.

  Use `getPeerSpiffeId` to read the calling service's SPIFFE ID from the header as `{ id, trustDomain, path, namespace, serviceAccount }`, and match `id` against an allow list. `parseXfcc` returns every element for other identities, and `parseDistinguishedName` reads a `subject` or `issuer`.

  The defaults close the gaps a crafted text-format SAN can open: `format` is required, `maxElements` defaults to 1, `getPeerSpiffeId` rejects a text-format element with a DNS SAN unless `requireSingleSan` is `false`, and `issuer` is never returned from the text format. Every rejected input throws `XfccError` with a stable `code`; invalid options throw `TypeError`.
