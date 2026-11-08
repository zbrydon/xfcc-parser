# Benchmark results

Recorded 2026-11-08 in a single run, on a laptop that was also running other work (load average about 2.1). Treat differences under about 5% as noise.

- Machine: Apple M4 Pro, macOS 26.5.2
- Node v26.12.1
- Reproduce: `pnpm bench`, which builds the package and benchmarks `dist/`

## Headers

| Benchmark                 | `parseXfcc`           |
| ------------------------- | --------------------- |
| text, single element      | 430k ops/s (2.4 us)   |
| text, two elements        | 358k ops/s (2.8 us)   |
| json                      | 465k ops/s (2.2 us)   |
| text, Cert and Chain      | 49.5k ops/s (20.3 us) |
| reject, unknown key       | 1.85M ops/s (0.5 us)  |
| reject, invalid character | 1.77M ops/s (0.6 us)  |
| reject, too long          | 2.07M ops/s (0.5 us)  |

## Distinguished names

| Benchmark                      | `parseDistinguishedName` |
| ------------------------------ | ------------------------ |
| simple                         | 1.07M ops/s (1.0 us)     |
| escapes and a multi-valued RDN | 827k ops/s (1.2 us)      |

## Worst cases

Each input is just under the 1 MiB ceiling. Time per call, which grows linearly with the input, so at the default 64 KiB `maxLength` expect about 1/16 of these.

| Benchmark                   | `parseXfcc` |
| --------------------------- | ----------- |
| long URI                    | 8.52 ms     |
| percent-encoded URI         | 12.99 ms    |
| many colons in an authority | 16.89 ms    |
| unterminated quote          | 2.55 ms     |
| percent-encoded Cert        | 6.36 ms     |
| Subject of escapes          | 5.51 ms     |
| many DNS pairs              | 21.44 ms    |
| JSON escapes                | 5.53 ms     |
| JSON list                   | 24.33 ms    |
| whitespace                  | 3.50 ms     |

| Benchmark | `parseDistinguishedName` |
| --------- | ------------------------ |
| escapes   | 1.60 ms                  |
| many RDNs | 43.70 ms                 |
| non-ASCII | 4.16 ms                  |
