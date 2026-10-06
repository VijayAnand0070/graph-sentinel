---
title: GraphSentinel LANL Transfer
emoji: 🛡️
colorFrom: indigo
colorTo: red
sdk: docker
app_port: 7860
pinned: false
license: mit
---

# GraphSentinel LANL Transfer

Private one-time transfer worker. It downloads the official LANL authentication and red-team
archives, performs complete gzip/schema/timestamp validation, creates a provenance manifest,
and uploads the validated files to a private Hugging Face dataset repository.

