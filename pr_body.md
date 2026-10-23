- closes #282
- closes #284
- closes #285
- closes #286
- closes #499
- closes #500
- closes #501
- closes #505

### Changes Made:

#### docs: reference page for token_supply_change (#499)
- **Created** `docs/rules/token-supply-change.md` - Reference page for the rule type, covering:
  - What events it matches (SEP-41 `mint` and `burn`) and what it does not (`clawback`, `transfer`, `set_admin`)
  - The `direction` parameter (`mint` / `burn` / `any`, default `any`) and the `min_amount` threshold
  - Why amounts are decimal strings (i128 precision lost to float64 in JSON numbers)
  - How it relates to `token_event` with `event: mint` — one rule instead of two
  - curl examples for each parameter combination, and the create-time validation rules
- **Updated** `docs/rules/params.md` - Added the `token_supply_change` parameter table and a complete valid params document
- **Updated** `docs/SUMMARY.md` - Added `token_supply_change` to the rule reference table
- **Updated** `docs/guides/monitoring-a-token.md` - Added a pointer from the `token_event` walkthrough to `token_supply_change` for supply-change monitoring
- **Updated** `internal/docs/docs_test.go` - Pinned the new page in `pagesAddedHere` so the SUMMARY.md link contract and the relative-link checker cover it

#### test(secrets): cover the env provider, IsReference, WithTTL and Schemes (#500)
- **Added** `TestIsReference` - Table-driven test over the supported schemes, a plain literal, an empty string, a URL and a value containing `://`
- **Added** `TestNewEnvProvider` - Resolves a set variable, and reports an unset variable as an error rather than an empty string
- **Added** `TestWithTTL` - `WithTTL` sets the cache lifetime, and a non-positive duration disables caching
- **Added** `TestSchemes` - `Schemes()` returns the registered provider names
- **Added** `TestVaultProviderScheme` - The Vault provider's `Scheme()` is `"vault"`

#### test(stellar): cover partsToBig at the int128 and int256 boundaries (#501)
- **Added** `TestPartsToBig` - Table-driven test over the boundaries:
  - Zero and one
  - `math.MaxInt64` and `math.MinInt64` as the high part
  - A single rest part, and two rest parts (`1, 2` → `258`)
  - The u128 `hi`/`lo` cases, including the all-ones maximum
  - An i256 with all parts zero, and an i256 with all parts at their maximum
  - A negative high part

#### test(notify): cover the dispatcher's DisableAfterFailures and WithMetrics options (#505)
- **Added** `TestDispatchDisableAfterFailuresBasic` - The default (unset) threshold never auto-disables, and the health update carries no `DisableAfter`
- **Added** `TestDispatchDisableAfterFailuresThreshold` - `WithDisableAfterFailures(4)` reaches the store as `DisableAfter: 4` on every recorded health update
- **Added** `TestDispatchWithMetricsNilSafe` - `WithMetrics(nil)` is nil-safe: a delivery still succeeds and no metric call panics

### Verification

- `go build ./...`
- `go vet ./...`
- `go test ./... -count=1`
- `golangci-lint run` (0 issues)
