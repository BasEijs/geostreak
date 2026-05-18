# Future Ideas

Scratchpad for design alternatives we considered but didn't ship. Not a roadmap — just so they don't get lost.

## Un-built question types (from the diversity brainstorm)

Tier 1 shipped on 2026-05-18 (8 new question types: borders, capital→country, city→country, province→place, two population battles, shape, satellite). What's left:

### Tier 2 — Small data add (one new field per country/place)

Each of these needs one new field added to `COUNTRY_EXTRA` (or a small lookup constant). Build cost per question is the same as a regular MC type once the data is in.

- **Language MC** — add `languages: ["French"]` per country. "What language is spoken in Senegal?" — MC in Medium, typed in Jeroen. ~1h data, ~30 min build.
- **Demonym MC** — add `demonym: "French"` per country. "What are people from Iceland called?" Same shape as language. ~1h data, ~20 min build.
- **EU/NATO/UN membership** — store as `{eu, nato, un}` bools or a Set. Question shapes: "Is X in the EU?" (yes/no), or "Which of these is in NATO?" (MC). ~30 min data, ~30 min build.
- **Year of independence** — add `independence: 1776`. MC by decade in Medium, exact ± tolerance in Jeroen. Hardest data to source consistently (contested cases — UK, Japan). ~2h data, ~30 min build.
- **Currency text MC** — add `currency: "Euro"`. "What currency does Portugal use?" or reverse. ~1h data, ~30 min build.
- **Borders MC — NL provinces variant** — build a 12-province adjacency map by hand. "Which province borders Gelderland?" MC. ~15 min data, ~30 min build.
- **Borders multi-select (World)** — Bas's original idea was multi-select, but Tier 1 shipped single-select MC. A multi-select variant ("pick all countries that border France") would add a different question feel and reward deeper knowledge. Needs a new UI pattern (checkboxes + submit). ~1h.
- **Time zone MC** — add `tz: "UTC+1"` per country. "Which UTC offset is Argentina in?" Ignore DST. Natural battle variant: "Is it later right now in Tokyo or Mumbai?" ~1h data, ~30 min build.
- **Driving side** — add `drivingSide: "right"|"left"`. Quick yes/no or "pick the one that drives on the left." Trivia-feel question that mixes up rhythm. ~30 min data, ~20 min build.
- **Calling code MC** — add `callingCode: "+33"`. Bidirectional: "+47 is which country?" or "What's Japan's calling code?" ~45 min data, ~30 min build.
- **Country TLD MC** — add `tld: ".nl"`. Same shape as calling code. Could combine with calling code into a single "internet/phone identity" question type. ~45 min data, ~30 min build.
- **Landlocked or coastal** — add `landlocked: true`. "Which of these 4 is landlocked?" MC. Doubles as a teaching question — most players underestimate how many landlocked countries there are. ~30 min data, ~20 min build.
- **Hemisphere** — *no new data needed* if capital coords are already in place. "Northern or Southern hemisphere?" yes/no, or a 4-way N/S × E/W picker. ~0 data, ~30 min build.
- **NL — provinciehoofdstad** — 12-entry hand-built map. "Wat is de hoofdstad van Drenthe?" → Assen. Symmetric pair to the existing NL province question. ~10 min data, ~30 min build.
- **Flag color count / palette** — add `flagColors: ["red","white","blue"]` per country. "How many colors in this flag?" or "Which flag uses only red and white?" Reuses existing flag asset. ~1.5h data (some judgement calls on what counts as a color), ~30 min build.
- **Country anagram** — *no data add*. Scramble the letters of a country or capital name; type the unscrambled answer. Pure algorithmic — gives Jeroen Mode a wordplay variant. ~0 data, ~30 min build.

### Tier 3 — Bigger data lift

- **Higher/lower elevation** — highest-peak metres per country. ~120 entries to source. Same "battle" UI as population.
- **Higher/lower GDP or HDI** — needs GDP/HDI per country. Politically sensitive when out of date. Same "battle" UI.
- **Closer/further** — needs country center coords (cheap from topojson centroid). "Is Algeria closer to Spain than to Egypt?" The novelty is small though — feels niche.
- **River longer/shorter** — new `RIVERS` dataset, ~50 famous rivers with lengths. Same "battle" UI.
- **Continent/region sorting variants** — reuses existing match infra. Tag countries with finer regions (Balkans, SE Asia, Maghreb) and sort by those. Needs a `region` field per country.
- **Area battle** — add `area_km2` per country. Same battle UI as population. "Bigger: Mongolia or Argentina?" Surprise factor (Mongolia is bigger than most expect) makes it genuinely educational. ~120 entries, trivially sourceable from Wikipedia.
- **Country sandwich** — uses the borders graph that the Tier 2 multi-select idea would already build. "Which country lies between France and Spain?" → Andorra. Or "Which country borders both Germany and Italy?" → Austria/Switzerland. Algorithmic; no new data once borders exist.
- **UNESCO World Heritage count battle** — count of sites per country. "More UNESCO sites: Italy or France?" (Italy by 1 at last check). Surprising answers, same battle UI. ~120 entries.
- **Köppen climate MC** — primary climate code per country (Af/BWh/Cfb/etc.) collapsed into 5–6 human-readable buckets ("hot desert", "temperate oceanic", etc.). "What's Egypt's main climate?" Educational and teachable. ~2h data (judgement calls on countries that span zones), ~30 min build.
- **Coord → country click** — give a lat/lon, ask user to click the country it lands in. Reuses existing map-click infra; data is just a curated list of "interesting" coordinates (or random points filtered to land via the existing TopoJSON). ~1h to curate a good seed list.

### Tier 4 — Hard (external assets, licensing, hosting)

- **Landmark photos** — show a photo of the Eiffel Tower / Colosseum / Christ the Redeemer; ask which country/city. Need ~100+ photo URLs with confirmed licenses (Wikimedia CC works but you'd want a stable host) and a curated landmark→country mapping. Photo loading adds latency. NL variant: Rijksmuseum, Euromast, etc.
- **Currency banknote/coin images** — same hosting/licensing problem as landmarks. Harder to source clean images.
- **License plate recognition** — niche; very few clean image sources; plate format varies a lot. Marginal value vs effort.

### Notes for whoever picks these up

- The 4 "battle" ideas (elevation, GDP, HDI, river length) all share the same 2-choice UI we already shipped in `buildPopBattleQ` — they'd be near-clones with different fields. Worth factoring out a generic `buildBattleQ(field, label)` helper if more than one of these lands.
- Tier 4 photo-based questions need a thinking pass on hosting before any build work: hotlinking Wikimedia is fragile, but bundling images blows up the Docker image size.
- Anything with year/date data (independence, founding) should store ISO dates not just years, so we can format per language later.
