"""Bounded native Ollama HTTP on explicit loopback, without redirects or retries."""

from __future__ import annotations

import http.client
import json
import math
import re
import time
from urllib.parse import urlsplit

LIMIT = 2_000_000


def decode(raw):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def finite(value):
        raise ValueError("Non-finite JSON: " + value)

    if len(raw) > LIMIT:
        raise ValueError("JSON exceeds byte limit")
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique, parse_constant=finite)


def endpoint_checked(value):
    url = urlsplit(value)
    if (
        url.scheme != "http"
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
        or url.path not in {"", "/"}
        or url.hostname not in {"127.0.0.1", "localhost", "::1"}
    ):
        raise ValueError("Use local Ollama: http://127.0.0.1:11434")
    port = url.port if url.port is not None else 11434
    if not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    host = "127.0.0.1" if url.hostname == "localhost" else url.hostname
    return host, port


class WireError(RuntimeError):
    pass


class LocalHTTP:
    def __init__(self, endpoint, timeout=180):
        self.host, self.port = endpoint_checked(endpoint)
        if (
            type(timeout) not in {float, int}
            or not math.isfinite(timeout)
            or not 0 < timeout <= 600
        ):
            raise ValueError("Timeout must be finite and within (0,600] seconds")
        self.timeout = timeout

    def call(self, method, path, body, destination):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        raw = bytearray()
        deadline = time.monotonic() + self.timeout
        try:
            connection.connect()
            sock = connection.sock
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            connection.request(method, path, body, {"Content-Type": "application/json"})
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            response = connection.getresponse()
            while response.length != 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Total request deadline exceeded")
                sock.settimeout(remaining)
                block = response.read1(min(65536, LIMIT + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
                if len(raw) > LIMIT:
                    raise WireError("HTTP response exceeds byte limit")
            if response.length not in {None, 0}:
                raise WireError("Incomplete HTTP response")
            if response.status != 200:
                raise WireError("HTTP " + str(response.status) + "; no retry or redirect")
            return decode(bytes(raw))
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise WireError(type(exc).__name__ + ": " + str(exc)) from exc
        finally:
            connection.close()
            # Exact success/error bytes are always retained; existing files are not overwritten.
            with destination.open("xb") as target:
                target.write(raw)


def identity(client, folder, name, expected=None):
    folder.mkdir()
    version = client.call("GET", "/api/version", None, folder / "version.json")
    tags = client.call("GET", "/api/tags", None, folder / "tags.json")
    return identity_checked(version, tags, name, expected)


def identity_checked(version, tags, name, expected=None):
    if not isinstance(version, dict) or not isinstance(version.get("version"), str):
        raise ValueError("Ollama version missing")
    if not isinstance(tags, dict) or not isinstance(tags.get("models"), list):
        raise ValueError("Local model inventory missing")
    models = [m for m in tags["models"] if isinstance(m, dict) and m.get("name") == name]
    if len(models) != 1:
        raise ValueError("Required model is missing/ambiguous; no model is downloaded")
    model = models[0]
    digest = model.get("digest", "").removeprefix("sha256:")
    if (
        not re.fullmatch(r"[0-9a-f]{64}", digest)
        or any(model.get(k) for k in ("remote_host", "remote_model"))
        or ":cloud" in name.casefold()
        or not isinstance(model.get("details"), dict)
        or model["details"].get("format") != "gguf"
    ):
        raise ValueError("Require an identified local GGUF model, not a cloud alias")
    result = {
        "name": name,
        "digest": digest,
        "details": model["details"],
        "ollama_version": version["version"],
    }
    if expected is not None and result != expected:
        raise ValueError("Ollama/model identity changed during review")
    return result


def runtime(client, folder, expected, context):
    state = client.call("GET", "/api/ps", None, folder / "runtime.json")
    runtime_checked(state, expected, context)
    return state


def runtime_checked(state, expected, context):
    models = state.get("models") if isinstance(state, dict) else None
    if not isinstance(models, list):
        raise ValueError("Runtime model inventory missing")
    matches = [m for m in models if isinstance(m, dict) and m.get("name") == expected["name"]]
    if (
        len(matches) != 1
        or matches[0].get("digest", "").removeprefix("sha256:") != expected["digest"]
        or type(matches[0].get("context_length")) is not int
        or matches[0]["context_length"] != context
    ):
        raise ValueError("Runtime model digest/context was not confirmed")
    return state
