# PRD: `corgea deps`

**Format:** One-page bet
**Replaces:** the 21-section spec until we have evidence

## The bet

Developers will adopt a dependency tool that answers "why is this package here and can it drift" faster than one that hands them another CVE list. We can prove this in three weeks using a CLI we already ship to paying customers.

## The user

One person: the AppSec engineer at a company already paying for Corgea. They own dependency risk across many repos. They feel the pain ("where is package X, why is it here") and they can say yes. Not "developers, AppSec, platform, compliance." That is nobody.

## The problem, in their words

"I know we have a vulnerable package somewhere. I cannot tell you which repos, which version, why it is there, or whether the build will pull a different version tomorrow."

## The riskiest assumption

Developers will trust the findings instead of disabling the tool. The PRD lists this as Risk #1. It is not a risk. It is the whole question. Everything else is downstream of it.

## The experiment

Build the smallest thing that tests trust:

- `corgea deps scan` and `corgea deps explain`, npm only, four deterministic findings.
- Three weeks. Inside the existing CLI.
- Hand-deliver it to ten existing customers. Do things that do not scale: DM them, watch them run it, take notes.

## The demo that sells it

"You ran `npm install` and got 1,400 packages. Which one pulled in `event-stream`?"

`corgea deps explain event-stream`

`root > a > b > event-stream`. Ten seconds. No competitor makes provenance one command.

## The one metric

Of developers who run `deps scan` once, how many run it again within seven days. Retention and word of mouth. Not repos scanned, not SBOMs generated.

## The unfair advantage

This ships inside a CLI that paying customers already run. Distribution is free. Treat Corgea integration as item zero, not FR10. Add `deps scan` to the next release and email the twenty biggest accounts by hand.

## Not now

`diff`, `sbom`, policy-as-code, `fix`, license and registry findings, the vulnerable-package finding, Go, Java, Python, the platform dashboard, the three-phase launch plan. All of it waits for evidence the wedge works. SBOM and license checks are parity features; every competitor has them and they win nobody.

## Kill or double down

After three weeks with ten customers:

- **Double down** if developers run `explain` again, fix findings, and tell teammates. Then build `diff` and the next ecosystem.
- **Stop and fix** if they run it once and ignore it. The findings are not trusted. Fix that before adding anything.
