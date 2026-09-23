---
name: Generated client typings
description: TypeScript configuration needed by the generated API client.
---

Generated API client code uses `Headers.entries()`. Any composite library that compiles the client must include both `dom` and `dom.iterable` in its TypeScript `lib` settings.

**Why:** The default workspace library settings compiled `Headers` without the iterable methods, causing codegen's chained typecheck to fail even though the generated client itself was valid.

**How to apply:** If codegen reports missing `Headers.entries()` or similar DOM iterator members, check the compiling library's `tsconfig.json` before changing generated output.