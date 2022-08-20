# Contributing to Certomancer


## Code of conduct

Interactions between contributors are governed by the
[Code of Conduct](CODE_OF_CONDUCT.md),
which is based on the standard Contributor Covenant template. Discussion is
allowed and encouraged, but be civil, play nice, share your toys; the usual.


## Use of the issue tracker and discussion forum

### Questions about Certomancer

**Do not ask for support on the issue tracker.** The issue tracker is for bug
reports and actionable feature requests. Questions related to Certomancer usage
and development should be asked in the discussion forum instead.

Note that community support is provided on a best-effort basis without any
service level guarantees.


### Bug reports

If you think you've encountered a bug in Certomancer, you can submit 
a bug report in the issue tracker by filling out the bug report template.
Please include all relevant information indicated in the template.

For bugs in library code, always include a stack trace, and (if at all possible)
a minimal, reproducible code sample.


### New features

If you have an idea for a feature, consider allowing for some discussion on
the discussion forum before creating a feature request in the issue tracker
or submitting a PR. This allows for smoother collaboration, ensures that
feature requests stay within the project's scope, and increases the chances
that your feature request or PR will be worked on and/or reviewed.

Additionally, consider whether your feature could be implemented using the 
existing plugin system. If so, that might be preferable, depending on how
broadly applicable the feature would be.


## Compatibility

Currently, Certomancer aims to remain compatible with Python versions 3.7 and up,
and this is expected of new contributions as well (for the time being).

Dependency changes (both version changes and new dependencies) must always be
motivated. Besides issues of technical compatibility, also consider the
licence under which said dependencies are made available.

Breaking changes between releases are allowed (at least until we reach `1.0.0`) but
must be documented in a way that can be included in the release notes.

## Tests

As a general rule, all PRs should strive towards full coverage on new code, but
given the rather experimental nature of the project and its target audience
as a testing tool, there's quite a bit of leeway.

In addition, keep in mind the following when writing test cases:

 * Test both the "happy path" (i.e. expected input) and error behaviour.
 * When committing a bugfix, verify that your new tests fail before the fix
   was applied.
 * Don't just shoot for high statement coverage. Diversity in scenarios is
   hard to measure, but no less important.


## Code style

Code style is `black` with an 80-character limit for each line of code,
and string quote normalisation turned off.
PRs that don't fit the code style will be rejected by the linter, so please
format your code before submitting.

Here are some additional pointers:

 * Avoid overly long function definitions.
 * Avoid letting builtin exceptions (`KeyError`, `ValueError`, ...) bubble up
   through public API entry points. These can be hard to catch and handle properly.
 * Docstrings must be written in ReStructured Text.
 * All new public API entry points should be documented. Documentation may be
   omitted from internal API functions if their purpose is sufficiently clear.
 * Exceeding the 80-character limit is permissible in documentation files when
   a workaround would be overly burdensome.


## Copyright issues

Certomancer is distributed under the [MIT licence](LICENSE), and explicitly does
*not* require its contributors to sign a contributor licence agreement (CLA).
Our approach is instead based on the
[Developer certificate of origin (DCO)][dco], reproduced below.

[dco]: https://developercertificate.org/

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.

```

In particular, the DCO allows you to retain ownership of your changes,
while permitting them to be distributed under the terms of the project's
licence.
