"""Security-focused streaming EDA summaries derived from causal features."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from graphsentinel.features.causal import FeatureRecord


@dataclass(slots=True)
class SecurityEdaAccumulator:
    events: int = 0
    positives: int = 0
    successes: int = 0
    new_pairs: int = 0
    users: set[int] = field(default_factory=set)
    hosts: set[int] = field(default_factory=set)
    day_counts: Counter[int] = field(default_factory=Counter)
    hour_counts: Counter[int] = field(default_factory=Counter)
    user_activity: Counter[int] = field(default_factory=Counter)
    destination_activity: Counter[int] = field(default_factory=Counter)
    positive_users: Counter[int] = field(default_factory=Counter)
    positive_destinations: Counter[int] = field(default_factory=Counter)
    max_user_fanout_5m: int = 0
    max_source_fanout_1h: int = 0
    failure_context_events: int = 0

    def observe(self, record: FeatureRecord) -> None:
        self.events += 1
        self.positives += record.label_redteam
        self.successes += record.success
        self.new_pairs += record.is_new_pair
        self.users.add(record.src_user_id)
        self.hosts.update((record.src_host_id, record.dst_host_id))
        self.day_counts[record.day] += 1
        hour = (record.timestamp % 86_400) // 3_600
        self.hour_counts[hour] += 1
        self.user_activity[record.src_user_id] += 1
        self.destination_activity[record.dst_host_id] += 1
        self.max_user_fanout_5m = max(self.max_user_fanout_5m, record.user_unique_dst_5m)
        self.max_source_fanout_1h = max(self.max_source_fanout_1h, record.src_host_unique_dst_1h)
        self.failure_context_events += int(record.failures_before_success_15m > 0)
        if record.label_redteam:
            self.positive_users[record.src_user_id] += 1
            self.positive_destinations[record.dst_host_id] += 1

    def to_dict(self, *, top_k: int = 20) -> dict[str, object]:
        if top_k <= 0:
            raise ValueError("top_k must be positive")
        return {
            "events": self.events,
            "redteam_events": self.positives,
            "redteam_prevalence": self.positives / self.events if self.events else 0.0,
            "success_rate": self.successes / self.events if self.events else 0.0,
            "new_pair_rate": self.new_pairs / self.events if self.events else 0.0,
            "unique_source_users": len(self.users),
            "unique_hosts": len(self.hosts),
            "events_with_failure_before_success": self.failure_context_events,
            "max_user_fanout_5m": self.max_user_fanout_5m,
            "max_source_host_fanout_1h": self.max_source_fanout_1h,
            "events_by_day": dict(sorted(self.day_counts.items())),
            "events_by_hour": dict(sorted(self.hour_counts.items())),
            "top_active_users": self.user_activity.most_common(top_k),
            "top_destinations": self.destination_activity.most_common(top_k),
            "top_redteam_users": self.positive_users.most_common(top_k),
            "top_redteam_destinations": self.positive_destinations.most_common(top_k),
            "modeling_consequences": [
                "fan-out maxima validate bounded rolling destination features",
                "new-pair rate establishes the pure novelty baseline",
                "failure-before-success counts quantify credential-attempt context",
                "hourly activity supports cyclic time features",
                "red-team prevalence confirms rare-event ranking metrics are required",
            ],
        }
