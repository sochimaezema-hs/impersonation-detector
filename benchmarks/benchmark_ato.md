# Account-takeover benchmark

Flagged = action hold or block (warn is a step-up challenge, counted as allow here).

400 synthetic accounts (half benign tails, half attack scenarios), seed 0. Campaign alerts: 2.

| Detector | recall | FPR | stuffing_then_chain | new_country_payout | impossible_travel_reset | mass_messaging_after_new_device | mfa_disable_recovery | shared_ip_campaign | quiet_new_device_payout | stolen_known_device |
|---|---|---|---|---|---|---|---|---|---|---|
| per_account | 0.84 | 0.01 | 1.00 | 1.00 | 1.00 | 0.72 | 1.00 | 0.00 | 1.00 | 1.00 |
| per_account+campaign_ip | 1.00 | 0.01 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
