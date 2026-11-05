# Synthetic migration review

All names and addresses are invented; addresses use documentation ranges.

Both snapshots reference `demo-client` and `demo-service` over TCP/443. Rule identifiers differ, but identifiers are not part of the compared signature. The rule report returns `PASS`.

CSM resolves `demo-service` to `198.51.100.10/32`; FMC resolves it to `198.51.100.20/32`. The object report returns `FAIL` and identifies the affected rules. The overall exit code is 1.

```bash
python compare.py examples/csm.json examples/fmc.json
python compare.py examples/csm.json examples/csm.json
```

The second command returns `PASS` with exit code 0. Append `--output-dir reports/demo-001` to save reports; choose a new directory per run.
