# Steps for releasing on GitHub

This document assumes that either a release branch was being worked on, or the
code changes for the next release are already in the main branch.

1. Make sure that Changelog.md is finalized with the immediate release as the
   latest release documented there.
2. Make sure all relevant PRs in the content repo are merged.
3. Run all the update scripts:
   ```
   make update_cert_fingerprints
   make update_container_documentation
   make update_padded_macs
   make update_root_key_file
   make update_expire_sectxt_pgp_test
   make translate_content_to_main
   ```
4. Make a release branch for the x.y version if not already present (e.g., release/1.8.x).
5. Make a release on GitHub:
   1. Use tag 'vx.x.x' e.g., v1.2.3 for the release
   2. Use release title: x.x.x
   3. For the description use the contents of the Changelog.md for this release
6. Update the Changelog.md for the next release and commit with something like:
   "- Bump for next version.".
7. Done.
