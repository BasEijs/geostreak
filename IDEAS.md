# Future Ideas

Scratchpad for design alternatives we considered but didn't ship. Not a roadmap — just so they don't get lost.

## Population MC — alternative difficulty knobs

The current implementation (shipped 2026-05-18) uses dynamic log-scale buckets in `buildPopulationQ` ([backend/public/index.html](backend/public/index.html)). It replaced the old "closest 3 numeric distractors" approach, which was too hard in Medium because the wrong answers were always within a few million of the correct value.

If buckets later feel too easy, or if we want more knobs to tune difficulty per-mode, these are the alternatives that were on the table:

### Spread distractors out (Millionaire-style)

Keep precise numeric MC, but instead of the 3 closest values, pick **1 close + 1 medium-far + 1 far** wrong answer. Restores some signal-from-knowledge while staying harder than buckets.

- Could be the right fit for Jeroen MC if buckets ever feel too easy there.
- Implementation: same shape as the old code, but sort by closeness and stratify the picks (e.g., closest, ~3× away, ~10× away).

### Typed with wide margin

Same UX as Jeroen typed mode (`medium_pop_margin` setting, default 20%) but with a much larger margin in Medium — e.g. 40–50%. Removes MC entirely.

- Teaches actual numbers rather than ranges.
- Risk: typing on a phone or with a number-pad is fiddly compared to clicking; the game is desktop-only but still.
- Implementation: just route Medium to the typed branch with a separate `medium_pop_margin_wide` setting (or repurpose the existing one).

### Raise the population_min threshold for world mode

Currently `population_min` (default 5,000) only filters NL mode. World mode asks population for any country with `extra.pop` set. Adding a `world_population_min` setting (e.g. 20M) would restrict the pool to well-known large countries.

- Smallest code change of the four.
- Doesn't change the question itself — just makes the pool less obscure.
- Could be combined with any of the above.

### Notes for whoever picks this up

- The bucket stops `[0, 3, 10, 30, 100, 300, 1000, ∞]` are hardcoded. If we want admin control, those become a config string.
- The `population_mc` setting is global (not per-difficulty). If we want different Medium vs Jeroen behavior (e.g. buckets for Medium, spread distractors for Jeroen), we'd need to split that toggle or branch on `currentDiff` inside `buildPopulationQ`.
- Only ~42 countries currently have `pop` data in `COUNTRY_EXTRA`. Whatever direction we go, expanding that pool would help variety more than tweaking the question format.
