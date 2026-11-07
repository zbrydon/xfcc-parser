# Benchmark results

Recorded 2026-11-08 in a single run, on a laptop that was also running other work (load average about 1.8). Treat differences under about 5% as noise.

- Machine: Apple M4 Pro, macOS 26.5.2
- Node v26.12.1
- Reproduce: `pnpm bench`, which builds the package and benchmarks `dist/`

## Headers

| Benchmark                 | `parseXfcc`           |
| ------------------------- | --------------------- |
| text, single element      | 447k ops/s (2.3 us)   |
| text, two elements        | 374k ops/s (2.7 us)   |
| json                      | 478k ops/s (2.1 us)   |
| text, Cert and Chain      | 51.7k ops/s (19.5 us) |
| reject, unknown key       | 1.88M ops/s (0.5 us)  |
| reject, invalid character | 1.79M ops/s (0.6 us)  |
| reject, too long          | 2.11M ops/s (0.5 us)  |

## Distinguished names

| Benchmark                      | `parseDistinguishedName` |
| ------------------------------ | ------------------------ |
| simple                         | 1.09M ops/s (0.9 us)     |
| escapes and a multi-valued RDN | 836k ops/s (1.2 us)      |

## Worst cases

Each input is just under the 1 MiB ceiling. Time per call, which grows linearly with the input, so at the default 64 KiB `maxLength` expect about 1/16 of these.

| Benchmark                   | `parseXfcc` |
| --------------------------- | ----------- |
| long URI                    | 8.64 ms     |
| percent-encoded URI         | 12.72 ms    |
| many colons in an authority | 16.67 ms    |
| unterminated quote          | 2.45 ms     |
| percent-encoded Cert        | 6.20 ms     |
| Subject of escapes          | 5.42 ms     |
| many DNS pairs              | 21.59 ms    |
| JSON escapes                | 5.57 ms     |
| JSON list                   | 24.16 ms    |
| whitespace                  | 3.40 ms     |

| Benchmark | `parseDistinguishedName` |
| --------- | ------------------------ |
| escapes   | 1.58 ms                  |
| many RDNs | 43.62 ms                 |
| non-ASCII | 4.33 ms                  |
