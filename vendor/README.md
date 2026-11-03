# Vendored browser libraries

Kept in the repo so the dashboard's login page never loads code from a
third-party CDN.

| File | Source | Version | Integrity |
|---|---|---|---|
| `supabase-js-2.118.0.js` | npm `@supabase/supabase-js`, `dist/umd/supabase.js` | 2.118.0 (published 2026-10-15) | `sha384-TcHRA3zBbn+Lexh5n+Oil4guNPOS3rjNDpGRAN46u/s/mB2IZ50ceC6TYDU2yvgK` |

Tarball shasum matched the npm registry (`a590a3a0b301cb336c771a81c8d37a4bbc2647cf`) when copied.

**To upgrade:** `npm pack @supabase/supabase-js@<version>`, copy
`package/dist/umd/supabase.js` here under the new version name, recompute
the hash with
`openssl dgst -sha384 -binary <file> | openssl base64 -A`,
and update the `<script>` tag in `dashboard.html`.
