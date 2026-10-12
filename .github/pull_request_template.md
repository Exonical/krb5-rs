## Summary

<!-- What changes and why. -->

## MIT parity

<!-- The MIT krb5 1.22.2 sources this mirrors (file:line), and any deliberate deviations. -->

## Testing

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-features --all-targets -- -D warnings`
- [ ] `cargo test --all-features`
- [ ] Live MIT interop (`cargo test --all-features -- --ignored --test-threads=1`), if relevant

## Out of scope

<!-- Anything reviewers should not flag because another PR handles it. -->
