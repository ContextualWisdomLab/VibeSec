# Security

- Emit structural GitHub Actions poll-bound findings through production `_scan_file` using the existing `github-actions-transport-only-poll-bound` and `github-actions-transport-failure-budget-poll-bound` identities. Regex and analyzer hits for the same rule on the same file merge to one finding; helper loops, reversed comparisons, unreachable exits, and split `while`/`do` polls that regex adjacency misses can now be reported. Quoted or comment text stays negative. See issue #1087.
