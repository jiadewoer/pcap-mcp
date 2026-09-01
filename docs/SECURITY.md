# Security model

`pcap-mcp` treats every capture as attacker-controlled input. HTTP bodies and headers, DNS
names, User-Agent values, TLS SNI, and other decoded strings may all be chosen by a remote
peer. A prompt injection inside a packet can try to steal data, trigger another connected tool,
or quietly persuade an assistant to misclassify malicious traffic as harmless.

## Trust boundaries

The MCP client may select a tool and supply parameters. The server validates those parameters,
invokes `tshark` without a shell, converts bounded output into structured data, then applies
redaction and injection defenses before any result reaches the model.

| Threat | Input | Control | Implementation |
| --- | --- | --- | --- |
| Read arbitrary files through traversal or symlinks | `path` | Strict real-path resolution, allowed-directory and suffix lists | `tshark.resolve_capture` |
| Turn a filter into another tshark argument | `display_filter` | Character/length allowlist, no leading dash, argument-list subprocess, `shell=False` | `tshark.validate_filter` |
| Inject arbitrary output fields or statistics modules | Field/spec parameters | Explicit field grammar, count cap, statistics allowlist | `tshark.validate_fields`, `tshark.stat` |
| Exhaust CPU, memory, or context | Capture and output | File-size limit, subprocess timeout, row caps, `truncated` metadata | `config.Settings`, `tshark.fields` |
| Leak host identifiers and credentials | Tool result | Default-on IP/MAC/secret redaction; credential tool extracts locations only | `security.redact`, `analysis.cleartext_credentials` |
| Make the model follow packet text | Decoded peer strings | Pattern detection, Unicode-control removal, matched-text neutralization, untrusted-data wrapper | `security.guard_output` |
| Use injection to conceal malicious traffic | Decoded peer strings | Security banner instructs the client to disclose the attempted manipulation | `security.guard_output` |

## Secure defaults

- With no `PCAP_MCP_ALLOWED_DIRS`, the server reads no captures.
- `PCAP_MCP_REDACT` defaults to `on`. Disabling it is an explicit operator decision.
- Cleartext-credential analysis never requests or returns a password, token, cookie, or
  authorization value.
- All capture-derived text is wrapped in `<untrusted_pcap_data>`.
- No command uses a shell. Standard output is reserved for MCP's stdio transport.

## Prompt-injection fixture

Run `python scripts/craft_injection_pcap.py` to recreate
`tests/fixtures/injection_demo.pcap`. Its complete TCP handshake and HTTP response body contain an
instruction-override phrase and a zero-width character. The fixture is deliberately harmless and exists to verify that results
receive a warning, the matching text is broken up, invisible controls are removed, and the full
result stays inside the trust marker.

## Residual risk

Pattern matching cannot catch every semantic or obfuscated injection. Redaction is best-effort
and not a substitute for data classification. Wireshark dissectors and the Python dependencies
remain part of the trusted computing base and should be patched. Heuristic scan findings are
leads for human review, not security verdicts.

Please report suspected vulnerabilities privately to the repository owner rather than including
sensitive packet data in a public issue.
