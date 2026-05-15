# Audit Log

Every decision pkggate makes is appended to `./audit.log` as JSON Lines — one event per line, ready for ingestion by any SIEM, log shipper, or `jq` pipeline.

---

## Event format

```json
{
  "ts": "2026-04-20T10:12:03Z",
  "action": "block",
  "package": "passports-js",
  "version": "0.0.1-security",
  "rule": "block_malicious",
  "source": "MAL-2024-88"
}
```

| Field | Description |
|---|---|
| `ts` | ISO 8601 timestamp (UTC) |
| `action` | `allow` or `block` |
| `package` | Package name |
| `version` | Package version |
| `rule` | Policy rule that triggered (null for `allow`) |
| `source` | Advisory ID or list entry that triggered (null if not applicable) |

---

## Tailing the log

```bash
tail -f audit.log | jq .
```

Filter for blocks only:

```bash
tail -f audit.log | jq 'select(.action == "block")'
```

Count blocks by rule over the last hour:

```bash
jq -r 'select(.action == "block") | .rule' audit.log | sort | uniq -c | sort -rn
```

---

## Log rotation

pkggate does not rotate the audit log itself. Use `logrotate` or your container orchestrator's log driver to manage log size. Example `logrotate` config:

```
/path/to/audit.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    copytruncate
}
```

---

## SIEM integration

The JSON Lines format is natively supported by most log shippers:

=== "Filebeat"

    ```yaml
    filebeat.inputs:
      - type: filestream
        paths:
          - /app/audit.log
        parsers:
          - ndjson:
              target: pkggate
    ```

=== "Fluent Bit"

    ```ini
    [INPUT]
        Name  tail
        Path  /app/audit.log
        Parser json
        Tag   pkggate.audit
    ```

=== "Vector"

    ```toml
    [sources.pkggate]
    type = "file"
    include = ["/app/audit.log"]
    line_delimiter = "\n"

    [transforms.parse_pkggate]
    type   = "remap"
    inputs = ["pkggate"]
    source = '. = parse_json!(.message)'
    ```
