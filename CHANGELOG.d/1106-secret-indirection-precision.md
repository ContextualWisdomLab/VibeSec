### Security

- `hardcoded-password` no longer treats shell `$VAR` indirection or psql
  `PASSWORD :'name'` binds as committed secrets; `password='secret123'` still
  fires. `*.test.ts` / `*.test.mjs` / `*.spec.*` files are test context even
  under `src/`, so credential-free `postgresql://runtime.invalid/...` sentinels
  in tests are not deploy-blocking. Comments about prototypes or hidden
  authority fields are not `todo-skip-auth` unless they skip, disable, bypass,
  or defer authentication. LifeOS #247 `*.test.mjs` titles about author identity
  and `*.integration.test.*` files under `src/` stay non-deploy-blocking.
