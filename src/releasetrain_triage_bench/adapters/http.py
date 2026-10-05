"""Reference HTTP adapter: wraps a real triage system (your agentic
pipeline, or anyone else's) running behind an HTTP endpoint. This is the
adapter used to produce a paper's real reported numbers - it calls the
system's own unmodified server, over HTTP, rather than reimplementing any
of its logic (see this package's README for why reimplementing the
pipeline being evaluated is the one thing this package deliberately never
does).

Deliberately generic: the request/response shape is configurable via
`request_builder`/`response_parser` rather than hardcoded to one
specific API, since a goal of this package is to let a different triage
system be evaluated against the same benchmark without forking this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

import requests

from ..types import EcosystemComponent, TriagedUpdate


def default_request_builder(
    components: Sequence[EcosystemComponent], mode: str, feedback: str | None = None
) -> dict:
    payload: dict = {
        "components": [
            {"name": c.name, "version": c.installed_version, "vendor": c.vendor}
            for c in components
        ],
        "optimizeFor": mode,
    }
    if feedback:
        payload["feedback"] = feedback
    return payload


def default_response_parser(response_json: Any) -> list[TriagedUpdate]:
    rows = response_json.get("results", response_json) if isinstance(response_json, dict) else response_json
    return [
        TriagedUpdate(
            component=row["component"],
            order=row["order"],
            reasoning=row.get("reasoning", ""),
        )
        for row in rows
    ]


@dataclass
class HTTPTriageSystem:
    endpoint: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout_s: float = 60.0
    request_builder: Callable[[Sequence[EcosystemComponent], str, str | None], dict] = default_request_builder
    response_parser: Callable[[Any], list[TriagedUpdate]] = default_response_parser

    def triage(
        self, components: Sequence[EcosystemComponent], mode: str, feedback: str | None = None
    ) -> list[TriagedUpdate]:
        payload = self.request_builder(components, mode, feedback)
        resp = requests.post(self.endpoint, json=payload, headers=self.headers, timeout=self.timeout_s)
        resp.raise_for_status()
        return self.response_parser(resp.json())
