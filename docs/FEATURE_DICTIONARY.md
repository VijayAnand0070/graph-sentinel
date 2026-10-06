# Causal feature dictionary

Feature version: `auth-causal-v1`

All historical features use events with timestamps strictly less than the scored event. Events
sharing a timestamp are scored together and only then update state.

| Feature | Definition before event `t` |
|---|---|
| `hour_sin`, `hour_cos` | Cyclic encoding of dataset-relative hour |
| `delta_user_log` | `log1p` seconds since the source user's previous event; zero when unseen |
| `delta_pair_log` | `log1p` seconds since the source-user/destination-host pair; zero when unseen |
| `is_new_pair` | Pair has never appeared before `t` |
| `pair_frequency_1h` | Pair events in `(t-1h, t)` |
| `pair_rarity` | `1 / sqrt(1 + historical_pair_count)` |
| `user_unique_dst_5m/1h/24h` | Distinct destination hosts for the user in each trailing window |
| `user_auth_rate_5m` | Authentication count for the user in `(t-5m, t)` |
| `user_failure_rate_15m` | Failed fraction for the user in `(t-15m, t)` |
| `failures_before_success_15m` | Recent failure count, exposed only when the current event succeeds |
| `user_new_dst_ratio_1h` | Fraction of recent user events that introduced historically new destinations |
| `src_host_unique_dst_1h` | Distinct destinations contacted by the source host in `(t-1h, t)` |
| `dst_inbound_users_1h` | Distinct source users reaching the destination in `(t-1h, t)` |
| `destination_novelty` | `1 / (1 + historical distinct inbound users)` |
| `user_historical_degree` | All-time user-to-destination degree before `t` |
| `src_host_historical_degree` | All-time source-host-to-destination degree before `t` |
| `dst_historical_degree` | All-time distinct inbound-user degree before `t` |
| `rare_logon_score` | Negative log of Laplace-smoothed per-user logon-type probability |

Categorical IDs and the current event's success flag are retained as model inputs. Identity IDs
are metadata, not baseline features, to reduce memorization and improve defensibility.

