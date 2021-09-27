# Steps for releasing on GitHub

This document assumes that either a release branch was being worked on, or the
code changes for the next release are already in the master branch.

Even if the work was part of the master branch, it is advised to create a branch
and a PR for the release for cleaner workflow. Indicative branch name:
'release-v1.2.3'.

0. Make a release branch if not already present (e.g., release-v1.2.3)
1. Make sure that Changelog.md is finalized with the immediate release as the
   latest release documented there. (If creating a release branch as suggested
   above, this change shoud be there).
2. Run all the update scripts:
   ```
   make update_cert_fingerprints
   make update_padded_macs
   make update_root_key_file
   ```
3. Push everything to upstream.
4. Create the PR on GitHub.
5. Merge the PR and delete the branch on GitHub.
6. Make a release on GitHub:
   1. Use tag 'vx.x.x' e.g., v1.2.3 for the release
   2. Should be tagged on master usually
   3. Use release title: x.x.x
   4. For the description use the contents of the Changelog.md for this release
      (leave out the title since GitHub will use the title)
7. Update the Changelog.md for the next release and commit with something like:
   "- Bump for next version.".
8. Done.
