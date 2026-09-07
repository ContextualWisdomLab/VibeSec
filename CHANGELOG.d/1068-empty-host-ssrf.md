## Security

- Reject empty parsed hostnames before DNS resolution in URL validation so malformed HTTP(S) inputs cannot traverse the historical `socket.gaierror` fail-open path.
- Add the HIGH `python-ssrf-empty-host-fail-open` scanner rule with vulnerable/fixed security-corpus fixtures and production-path regression coverage for reviewed false-positive and false-negative boundaries.
