# Security policy

## Scope and safety
offline; passwords are never printed, logged or sent anywhere (output is masked); stdin input avoids writing them to disk. Intended for test data only.

## What was and was not tested
**Tested (automated, in CI and locally):** policy rules, entropy estimate, masking, stdin input and exit codes using made-up test passwords.

**Not tested:** real password databases or breached-password lists, Unicode edge cases, and any use as an actual enforcement control (the entropy estimate is rough).

## Reporting a problem
This is a small personal portfolio project, not a supported product. If you find a security issue, please open a GitHub issue **without** secrets, credentials or real system details, or use GitHub's "Report a vulnerability" button on the Security tab if it is enabled.
