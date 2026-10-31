---
slug: security
menu: 20
---
# Security model

Every feature of Bastion starts with abuser stories: who attacks, what they want and why. Each story names the weaknesses it exploits, and the build fails unless the code carries a mitigation for each of them and an attack test names the story.

The views below are not written by hand. They are generated at release time from the threat model in the repository, the mitigation attributes in the code and the attack tests. Open any story for the exact place in the code.

## At a glance

::: threatmodel overview

## How data moves

::: threatmodel dfd

## What we defend against

::: threatmodel matrix

## What the analyzer found

Findings come from the rule engine that checks the model. Some are recorded as false positives with a reason; the open ones are listed as they are.

::: threatmodel findings
