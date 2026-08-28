---
title: OpenQBW
sidebar_label: OpenQBW
---

# OpenQBW

[OpenQBW](https://github.com/Sigilweaver/OpenQBW) is the companion
project that uses OpenSQLAnywhere to read Intuit QuickBooks Desktop
`.QBW` company files.

- Project site: [https://sigilweaver.app/openqbw/docs/](https://sigilweaver.app/openqbw/docs/)
- Repository: [https://github.com/Sigilweaver/OpenQBW](https://github.com/Sigilweaver/OpenQBW)
- crates.io: [https://crates.io/crates/openqbw](https://crates.io/crates/openqbw)
- PyPI: [https://pypi.org/project/openqbw/](https://pypi.org/project/openqbw/)

## Architecture

```
.QBW file
   |
   v
 OpenQBW         (QuickBooks-specific research and catalog diagnostics)
   |             ^
   v             |
 opensqlany      |
   - ApModel ----+  (peel additive-progression obfuscation)
   - PageStore      (walk pages, verify CRC, parse slotted dirs)
   - typed rows     (bounded primitive; caller supplies schema)
```

OpenSQLAnywhere has no knowledge of the QuickBooks schema; it
exposes plaintext SA17 pages and the deobfuscation primitive.
OpenQBW provides the QuickBooks-specific research layer. It does not yet
provide a completed Enterprise 24 accounting extractor.
