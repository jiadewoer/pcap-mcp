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
| Exhaust CPU, memory, or context | Capture and output | File-size and subprocess-output byte limits, timeout, row caps, result-character cap | `config.Settings`, `tshark._run`, `server._ok` |
| Leak host identifiers and credentials | Tool result | Default-on IP/MAC/secret redaction; credential tool extracts locations only; custom fields limited to metadata | `security.redact`, `analysis.cleartext_credentials`, `analysis.display_filter` |
| Make the model follow packet text | Decoded peer strings | Pattern detection, Unicode-control removal, matched-text neutralization, untrusted-data wrapper | `security.guard_output` |
| Use injection to conceal malicious traffic | Decoded peer strings | Security banner instructs the client to disclose the attempted manipulation | `security.guard_output` |

## Secure defaults

- With no `PCAP_MCP_ALLOWED_DIRS`, the server reads no captures.
- `PCAP_MCP_REDACT` defaults to `on`. Disabling it is an explicit operator decision.
- Cleartext-credential analysis never requests or returns a password, token, cookie, or
  authorization value.
- Custom display-filter extraction cannot request raw payload or credential fields, or filter
  on raw protocol bytes. Other
  analysis tools may still expose peer-chosen metadata; redaction is best effort.
- HTTP request URIs are returned without query strings or fragments to avoid returning common
  session tokens; path segments and other metadata still need classification.
- A failed Wireshark subprocess is an error even if it emitted partial output.
- All capture-derived text is wrapped in `<untrusted_pcap_data>`.
- No command uses a shell. Standard output is reserved for MCP's stdio transport.

## Agent controller

The optional `pcap-mcp-agent` accepts one capture and one goal. It checks the capture locally,
forces a summary, hides the path argument from the model's tool schema, and overwrites any path
the model submits. Tool names, argument size, model rounds, call count, and accumulated evidence
size are bounded before making additional MCP calls. The server still validates every call.

The controller's evidence IDs show which tools ran; they do not verify that every model claim
correctly interprets the evidence. A real API provider receives the server's tool output, whose
redaction depends on `PCAP_MCP_REDACT`. Optional JSON evidence exports remain sensitive local
files. See [AGENT_GUIDE.md](AGENT_GUIDE.md) for the control loop and remaining limitations.

## Prompt-injection fixture

Run `python scripts/craft_injection_pcap.py` to recreate
`tests/fixtures/injection_demo.pcap`. Its complete TCP handshake and HTTP request User-Agent
contain an instruction-override phrase. The HTTP response body also contains a role-reset phrase
and a zero-width character, but raw response payload is not returned by the public tools.
The fixture has a fixed timestamp so it can be reproduced byte-for-byte. The HTTP request checks
that returned metadata receives a warning, the matching text is broken up, and the result stays
inside the trust marker.

## Residual risk

Pattern matching cannot catch every semantic or obfuscated injection. Redaction is best-effort
and not a substitute for data classification. DNS names, HTTP hosts, URIs, and user agents can
still contain sensitive values or attacker-written text. Processing a capture file has a
time-of-check/time-of-use window if a separate local actor changes the file after validation.
Wireshark dissectors and Python dependencies remain part of the trusted computing base and should
be patched. Heuristic scan findings are leads for human review, not security verdicts.

Please report suspected vulnerabilities privately to the repository owner rather than including
sensitive packet data in a public issue.
