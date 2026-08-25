# Discovery regression applications (8705-8710)

These applications are intentionally small, deterministic targets for ZAP Spider / AJAX Spider discovery regression testing. Client Spider can be added to the same matrix later without changing the applications.

## Common testbed endpoints

Every application has its own in-memory coverage counter:

- `GET /__testbed/expected` - expected business endpoints for that application.
- `GET /__testbed/coverage` - visited/missing endpoints and hit counts.
- `GET /__testbed/openapi.json` - an optional OpenAPI description of the expected endpoints. It is not linked from the UI.

The reset endpoint is deliberately not linked from any page and is not present in OpenAPI:

```bash
curl -X POST \
  -H 'X-Testbed-Control: zap-testbed-reset-v1' \
  http://127.0.0.1:8705/__testbed/control/reset
```

A request without the control header receives `404`. Requests under `/__testbed/*` are never counted as discovery coverage.

For all six applications at once:

```bash
./discovery-coverage.sh reset
./discovery-coverage.sh show
```

## 8705 - large-bundle-spa

Docker URL: `http://large-bundle-spa:8705`
Host URL: `http://127.0.0.1:8705`

Purpose: reproduce the response-body boundary seen in customer logs without making normal scans unnecessarily destructive.

Default resources:

- 900 KiB JS bundle - below 1 MiB.
- 1150 KiB JS bundle - just above 1 MiB.
- 1250 KiB lazy bundle - loaded only after a UI action.

Expected business endpoints:

- `/api/bootstrap`
- `/api/orders`
- `/api/lazy-reports`

A 4 MiB bundle exists at `/stress.html`, but this page is intentionally not linked and is not part of default coverage. Use it only for explicit stress testing.

### Why not load 10+ MiB bundles by default?

The goal is to cross the configured ZAP storage boundary, not to exhaust memory or disk. Repeated Active Scan requests against multi-megabyte resources can multiply traffic and storage quickly. A response slightly above the suspected 1 MiB boundary is enough to reproduce the class of failure. The larger stress resource is opt-in.

## 8706 - many-states-spa

Docker URL: `http://many-states-spa:8706`

Fifteen sequential DOM states are exposed one at a time. Entering state `N` calls `/api/state/NN`. This makes `maxCrawlStates` and crawl-depth regressions measurable rather than subjective.

## 8707 - runtime-discovery-spa

Docker URL: `http://runtime-discovery-spa:8707`

The initial HTML contains no business API paths. JavaScript assembles paths at runtime and triggers them through:

- page load,
- a custom element,
- a `div role=button`,
- a modal confirmation,
- a hash-route action,
- a dynamically inserted iframe.

## 8708 - large-api-response

Docker URL: `http://large-api-response:8708`

Linked API responses are approximately 100 KiB, 900 KiB and 1150 KiB. They all accept `?q=` so Spider/Active Scan behavior can be compared around the 1 MiB response-body boundary.

An unlinked 4 MiB endpoint exists at `/stress/4mb?q=manual` for explicit stress testing only.

## 8709 - bft-regression-spa

Docker URL: `http://bft-regression-spa:8709/app/`

Composite regression target:

- hash routing,
- custom menu elements,
- runtime-built URLs,
- business APIs outside `/app`,
- nested UI action (`/service/audit`),
- a 700 KiB application bundle (large enough to be realistic, below the 1 MiB boundary).

This scenario is intentionally safer than 8705: it tests interaction/discovery complexity without also forcing the response-size failure.

## 8710 - scope-noise

Docker URL: `http://scope-noise:8710`

The target page loads resources from these Docker network aliases:

- `scope-noise-cdn`
- `scope-noise-analytics`
- `scope-noise-updates`

The application coverage contains only `/api/local/a`, `/api/local/b`, `/api/local/c`. Requests to the alias hosts are reported separately in `noiseRequests` so scope pollution can be detected.

## Suggested AJAX Spider matrix

Start with the same scan target and vary one crawler control at a time, for example:

- 8706 with `maxCrawlStates=7`, then 15/20/unlimited.
- 8705/8708 with ZAP response-body limit below and above ~1.15 MiB.
- 8707 with default click elements vs expanded click configuration.
- 8709 with context limited to `/app/` vs the whole host.
- 8710 with strict context/scope and verify that alias-host traffic is not promoted into target scope.

After each scan, read `GET /__testbed/coverage` rather than inferring discovery quality from raw ZAP logs alone.
