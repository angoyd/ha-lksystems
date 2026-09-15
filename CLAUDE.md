# Working on this repo with Claude Code

This file is read automatically by Claude Code (and compatible tools) for
anyone working in this checkout - it's how contributors using an AI coding
assistant here end up working the same way, without each having to agree on
conventions from scratch.

For environment setup, running the two test suites, deploying to a live test
instance, and the optional Home Assistant MCP server integration, see the
**Contributing** section of [README.md](README.md) - it's not repeated here.

## Test-driven development

Work test-driven whenever a change touches `pylksystems` or anything under
`tests_ha/`'s coverage: write a test that captures the desired behavior
*before* touching production code, confirm it fails for the expected reason
(RED), then write the minimal implementation that makes it pass (GREEN),
then refactor with the test still green.

When fixing a bug, the failing test should reproduce the bug itself - ideally
in its own scenario, mirroring how it was actually observed - before the fix
lands, not just assert the fixed behavior after the fact. A test that was
never seen failing hasn't proven it tests anything.

This applies to any change with production-code impact and a test harness
capable of exercising it. It doesn't apply to pure docs/config changes,
one-off scratch scripts, or exploratory spikes.

## Clean code

Apply Robert C. Martin's Clean Code principles broadly - naming, function
shape, duplication, structure - not just comments.
([reference checklist](https://gist.github.com/wojteklu/73c6914cc446146b8b533c0988cf8d29))

- **Naming**: descriptive, unambiguous, no noise suffixes (`data2`, `_tmp`).
  Named constants over magic numbers/strings.
- **Functions**: small, single-purpose, one level of abstraction inside.
  Prefer 0-2 arguments; a boolean flag that branches internal behavior is
  usually two functions pretending to be one.
- **Duplication**: when the same pattern gets copied across a few
  classes/functions (this codebase's coordinator/entity split makes that easy
  to do by accident), look for the shared abstraction - a helper, a base
  method, a single call site - before accepting several near-identical
  copies.

### Comments

Self-documenting code (naming, structure) is the default. Add a comment only
when the *why*, or a genuinely non-obvious *what*, can't be expressed through
naming/structure alone - and never to restate what the next line already
says.

A comment must describe the code as it currently stands - never narrate a
diff ("this used to do X", "removed the Y check"). Git history already
records what changed. Before finalizing an edit, reread every comment you
touched: does it survive a rename/restructure attempt first, does it avoid
narrating a diff, is it not repeating the same rationale that already lives
at another site (state it once where it's owned, let other sites reach it
through the code), and does it avoid pointing at "elsewhere in the codebase"
without an actual import/call backing that connection.

**Never reference an issue/PR/ticket number in a comment or docstring, in any
file - no exception for test names/docstrings.** A number pointing at "the
tracker of the moment" goes stale the day the repo migrates host or the
tracker changes; the rationale belongs in prose with no number, or in the
commit message / PR description instead, never inline in code.

### Process

Once a change's tests are green, do a dedicated pass over the diff for
naming, duplication, function shape, and comment hygiene before considering
it done - TDD only verifies correctness, it doesn't catch those on its own.

## Verify against the real API before documenting behavior

This codebase has a strong existing convention (grep for "confirmed
empirically against the real API" across `custom_components/lksystems/` to
see it in practice) of not trusting assumptions about what the LK Systems API
actually returns or how a field behaves - `muteLeak`'s true semantics (a
static duration, not a live countdown) is a good example of behavior that
looked obvious from the field name and wasn't. Keep this up:

- Use the `lk-api-spec` skill (`.claude/skills/lk-api-spec/`) to check the
  real OpenAPI spec for an endpoint's actual request/response shape rather
  than guessing from `pylksystems`'s existing assumptions.
- For behavior the spec alone can't answer (timing, whether a value
  decrements, cache staleness), test against a real account/device before
  writing a comment that asserts it as fact. A comment that got this from
  testing should say so; one that's inferred/still a guess should say that
  too, not read as more certain than it is.

## GitHub issue workflow

Before filing a new issue, search the repo's existing open (and recently
closed) issues for the same problem first - `gh issue list` / `gh search
issues` against `angoyd/ha-lksystems`, not just a guess from memory. Filing a
duplicate splits discussion and tracking across two threads for no benefit;
if one is found, add to/comment on the existing issue instead of opening a
new one.

When told to start working on/implementing a specific issue, assign yourself
to it (`gh issue edit <n> --add-assignee <username>`) before starting -
that's the signal to anyone else looking at the tracker that it's actively
being worked, not just open and unclaimed.

### Labels

Beyond GitHub's own defaults (`bug`, `enhancement`, `question`, `duplicate`,
etc.), this repo has a few custom labels for states the defaults don't
cover:

- `tech-debt` - code cleanliness/duplication/dead-code work with no
  user-facing behavior change (as opposed to `enhancement`, a new feature or
  user-facing improvement).
- `waiting-for-response` - blocked on a *specific* person providing a
  *specific* piece of information (a data sample, a confirmation a fix
  works) - we know exactly what's needed and from whom, and can act as soon
  as it arrives.
- `needs-more-evidence` - not yet well-understood enough to define what
  "fixing" it would even look like - gathering reports/data points to find a
  pattern, with no single person or answer that unblocks it. Distinct from
  `waiting-for-response`: there, one specific reply moves things forward;
  here, the next step itself isn't known yet.

## Before opening a pull request

- Run `/simplify` (or an equivalent focused review) over the diff.
- Keep the branch's commit history clean - squash exploratory/investigation
  commits (anything that was only ever meant to be temporary, e.g. debug
  logging added to chase down a bug) rather than leaving them for reviewers
  to read through. `git cherry <base> HEAD` is useful for spotting which
  commits are actually unique to your branch when it's had `main` merged
  into it repeatedly.
- Full test suite green (`pytest tests/ -p no:homeassistant` and
  `pytest tests_ha/`, per the README).
