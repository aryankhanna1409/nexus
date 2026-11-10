"""Prometheus metrics (one registry per application instance)."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.requests = Counter("aegis_http_requests_total", "HTTP requests", ["method", "route", "status"],
                                registry=self.registry)
        self.latency = Histogram("aegis_http_request_duration_seconds", "HTTP request latency",
                                 ["method", "route"], registry=self.registry,
                                 buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30))
        self.errors = Counter("aegis_http_errors_total", "HTTP responses with status >= 500", ["route"],
                              registry=self.registry)
        self.rate_limited = Counter("aegis_rate_limited_total", "Requests rejected by the rate limiter",
                                    registry=self.registry)
        self.agent_actions = Counter("aegis_agent_actions_total", "Agent action outcomes", ["tool", "status"],
                                     registry=self.registry)
        self.rca_runs = Counter("aegis_rca_runs_total", "RCA investigations", ["provider", "status"],
                                registry=self.registry)

    def render(self) -> bytes:
        return generate_latest(self.registry)
