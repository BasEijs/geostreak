# CLAUDE.md — GeoStreak

## What is GeoStreak?

GeoStreak is a geography streak quiz web app. Players answer geography questions in a row; one wrong answer ends the streak. The app is hosted at `geostreak.eijsertjes.nl` and is intentionally desktop-only. The developer is Bas, and a colleague named Jeroen is the primary tester and inspiration — Jeroen is exceptionally skilled at geography, and the hardest difficulty ("Jeroen Mode") is named after him.

## Tech Stack

- **Backend**: Node.js / Express, SQLite via `better-sqlite3`, bcrypt for passwords, JWT for auth
- **Frontend**: Single-page HTML app (`backend/public/index.html`) — HTML and JS; CSS is in `backend/public/style.css`; data in `backend/public/data/`
- **Map**: Mapbox GL JS (style: `outdoors-v12`)
- **Border detection**: TopoJSON world-atlas (`countries-110m.json`) with ray-casting `pointInGeoJSON`
- **Deployment**: Docker → GitHub Container Registry (`ghcr.io/baseijs/geostreak:latest`), built via GitHub Actions, deployed via Komodo
- **Repo**: `BasEijs/geostreak` on GitHub

## Project Structure

```
geostreak/
├── backend/
│   ├── server.js              # Express API, SQLite setup, auth, scores, duel, admin settings
│   ├── public/
│   │   ├── index.html         # Frontend HTML + JS (single-page app, ~4500+ lines)
│   │   ├── style.css          # All CSS
│   │   └── data/
│   │       ├── countries.js   # EASY_COUNTRIES, MEDIUM_EXTRA, JEROEN_EXTRA, HISTORICAL_FLAGS
│   │       └── nl-places.js   # NL_PLACES (~316 Dutch woonplaatsen)
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml         # Local dev compose (NOT the production one)
├── .github/
│   └── workflows/
│       └── docker-build.yml   # CI/CD: builds Docker image, pushes to ghcr.io
└── CLAUDE.md
```

**Important**: The production `docker-compose.yml` lives in a separate `docker-stacks` repo managed by Komodo. The one in this repo is for local development only.

## Architecture Overview

### Backend (`server.js`)

The server handles:

- **Auth**: `/api/register`, `/api/login` — JWT-based, bcrypt hashed passwords
- **Scores**: `/api/scores` (POST to save, GET for leaderboard) — scores are stored per `user_id`, `difficulty`, `mode`, and `region`
- **Settings**: `/api/settings` (GET public settings), `/api/admin/settings` (POST, admin-only) — key-value pairs in a `settings` table
- **Admin**: `/api/admin/users` — user management, admin-only
- **Version**: `/api/version` — returns `APP_VERSION` and `GIT_SHA` from build args

Database tables:
- `users` — id, username, password (bcrypt), is_admin
- `scores` — id, user_id, streak, difficulty, mode, region, played_at
- `settings` — key, value (key-value store for all configurable settings)
- `duel_rooms` — id, code (6-char), host_user_id, guest_user_id, mode, region, difficulty, seed, status (waiting/active/finished), created_at
- `duel_progress` — room_id, user_id, streak, alive, updated_at (PRIMARY KEY: room_id+user_id)

Settings have server-side defaults. The full list includes timer durations, map thresholds, question type toggles, NL mode population thresholds, easter egg toggles, and neighbour leniency. All settings are exposed to the frontend via `GET /api/settings`.

Duel endpoints (all require auth):
- `POST /api/duel/create` — body: {mode, region, difficulty}; returns {code, seed, ...}
- `POST /api/duel/join/:code` — guest joins a waiting room
- `GET /api/duel/room/:code` — poll state; returns host/guest progress; lazy-expires after 2h
- `POST /api/duel/room/:code/start` — host only; sets status=active
- `POST /api/duel/room/:code/progress` — body: {streak, alive}; upserts progress; sets room finished when both alive=0

### Frontend (`index.html`)

This is a large single-page app. Key sections (in rough order):

1. **CSS** — in `style.css`: custom properties (dark theme, Jeroen purple theme), responsive layout, all component styles including duel
2. **HTML screens** — auth, menu, game, game-over, admin, duel-lobby, duel-waiting, duel-results
3. **Data** — `COUNTRIES` array (world) in `data/countries.js`, `NL_PLACES` array (~316 Dutch woonplaatsen) in `data/nl-places.js`
4. **Translation system** — `STRINGS` object with `en` and `nl` keys; `t()` helper returns current language strings; `currentLang` toggles between `'en'` and `'nl'`
5. **Game logic** — question generation, answer checking, streak tracking, timer
6. **Map** — Mapbox GL JS initialization, marker placement, label hiding, road visibility toggling
7. **Leaderboard** — `LB_REGIONS` config-driven tab system with region/mode/difficulty filters
8. **Admin panel** — collapsible `<details>` sections for Timers, World Mode, Question Types, NL Mode, Unlock Settings, Easter Eggs

### Game Modes & Regions

The game has two dimensions:

- **Mode**: `world` (Aardrijkskunde/Geography — mixed question types) or `topo` (Topografie/Map Only — map click questions only)
- **Region**: `world` (all countries) or `nl` (Dutch woonplaatsen)

The game setup flow is: **Mode → Region → Difficulty → Play**, presented as a 3-step modal with Next/Back/Start Game buttons.

### Difficulty Levels

- **Dumb Test** (`easy`) — World only, well-known countries, no map questions, multiple choice only
- **Medium** — All countries/places (filtered by population threshold in NL), all question types, map questions with optional neighbour leniency
- **Jeroen Mode** (`jeroen`) — Everything including disputed territories, typed answers instead of MC, tightest thresholds, no leniency

NL mode has no Dumb Test difficulty.

### Difficulty Unlocks

Harder difficulties are gated behind a minimum streak in the prerequisite difficulty, **per region+mode lane**. Each `(region, mode)` lane has its own independent unlock chain:

- **World Geography**: easy → medium → jeroen (full chain)
- **World Topo / NL Geography / NL Topo**: medium always unlocked (no `easy` to gate on) → jeroen (gated by streak in *that lane's* medium)

So reaching streak 10 on World Geography Dumb Test only unlocks World Geography Medium — it does **not** unlock NL Jeroen. Each lane is earned independently. This was an explicit design decision; if you're tempted to refactor toward a global unlock model, talk to Bas first.

Helpers (in `index.html`):
- `getUnlockPrereq(region, mode, diff)` — returns `{ prereqDiff, settingKey }` or `null` if always unlocked
- `isDifficultyUnlocked(diff, region, mode)` — bypasses for `devMode` and threshold=0; otherwise compares cached `allStats[`${region}_${mode}_${prereqDiff}`].best_streak` against threshold

The unlock check reuses the existing `/api/me/stats` endpoint (cached as `allStats`) — no new endpoint needed. Locked rows in the setup modal show a `<span class="lock-icon">🔒</span>` (a single swappable element, prepared for a future custom icon) and a tooltip on click. After a game, `endGame()` refreshes `allStats` and shows a "🔓 Medium unlocked!" celebration on the game-over screen if the *persisted* best_streak just crossed the threshold (compares `priorBest` captured before save against `newBest` after `loadAllStats()`).

Admin settings: `unlock_medium_streak` (default 10) and `unlock_jeroen_streak` (default 15). Setting either to 0 disables that gate. `devMode` bypasses all locks.

### Question Types

**World mode (Aardrijkskunde):**
- Capital MC / typed (Jeroen)
- Flag identification
- Map click (click inside country borders)
- Capital map click
- Population MC
- Match (drag countries to continents)

**World mode (Topografie):**
- Map click only

**NL mode:**
- `nl-province` — Which province is this city in? (MC or typed in Jeroen)
- `nl-map` — Click on the map of the Netherlands (distance-based, threshold scales with population)
- `nl-population` — How many inhabitants? (MC, only for places above configurable minimum)
- `nl-match` — Match 4 cities to their province (Medium) or randomly to gemeente/province (Jeroen)

### Map Scoring

**World mode**: Uses border detection via TopoJSON. `pointInGeoJSON` does ray-casting against country polygons.
- Clicking inside the correct country = correct
- Clicking a neighbouring country = correct (Medium only, if `medium_neighbor_correct` is enabled in admin)
- Disputed territories (ISO `null`, e.g. Kosovo, Somaliland) fall back to distance-based scoring with a separate admin-configurable threshold
- When wrong, the game tells you which country you actually clicked

**NL mode**: Distance-based. Threshold scales dynamically with population — large cities get tight thresholds, small villages get loose ones. Base thresholds are configurable in admin per difficulty.

**Map layer visibility**: World mode hides roads, buildings, and symbols. NL mode hides symbols only (keeps roads for orientation).

### Leaderboard System

Driven by the `LB_REGIONS` config array. Each entry defines:
- Region id, icon, label (EN/NL)
- Available modes with their own difficulty lists and defaults
- Default mode and difficulty

Adding a new region (e.g. Europe) = adding one entry to `LB_REGIONS` + providing data + question type support. The leaderboard tabs, mode toggles, and difficulty toggles render dynamically from this config.

Scores are stored and queried by `region + mode + difficulty` combination.

### Duel Mode

Two logged-in players get the same questions (seeded RNG) and play simultaneously. Each sees the opponent's live streak via polling.

**Flow**: Host creates room → gets 6-char code → shares it → guest joins → host starts → both play → results screen.

**Seeded RNG**: `makeSeededRng(seed)` (LCG) + `gameRng()` helper. Injected at exactly 2 points in `nextQuestion()`:
1. Question type selection: `cfg.questionTypes[Math.floor(gameRng() * ...)]`
2. `countryQueue` shuffle: `shuffleForGame(arr)` instead of `shuffle(arr)`

Wrong-answer choices still use `Math.random()` — only the question sequence needs to match.

**Polling**: 2s in waiting room, 3s during game. Rooms expire after 2h (lazy check on GET).

**Key state variables**: `isDuelMode`, `duelRoomCode`, `duelSeed`, `duelIsHost`, `duelRng`, `duelSetupMode` (flag that routes `confirmAndPlay()` to duel creation instead of normal game start).

**Duel scores also post to the regular leaderboard.** Rematch is host-only (creates new room with same settings).

### Translation / i18n

All user-facing strings must exist in both English and Dutch. The translation system uses a `STRINGS` object with `en` and `nl` sub-objects. The `t()` function returns the current language's strings. The language toggle is in the nav bar.

**Critical**: Every new user-facing string must be added in both languages. This has been a recurring source of bugs.

### Easter Eggs

- **Username "Jeroen"**: Blocked on registration (client + server, case-insensitive). Shows: "Jij mag niet meedoen, dan is het voor niemand meer leuk 😅"
- **"Ga werken man!"**: Toast notification after 10 minutes of play between 07:00–17:00 local time. Toggleable in admin settings.

### Admin Panel

Accessible only to admin users. Organized into collapsible `<details>` sections:
- **Timers** — per-difficulty timer durations
- **World Mode** — map thresholds, neighbour leniency toggle, disputed territory threshold
- **Question Types** — toggles for specific question types (second city, population MC, historical country names)
- **NL Mode** — population thresholds for Medium/Jeroen filtering, map thresholds, population question minimum
- **Unlock Settings** — streak thresholds to unlock Medium and Jeroen Mode (per-lane); 0 disables a gate
- **Easter Eggs** — toggle for "Ga werken man!"

## Deployment & CI/CD

### GitHub Actions (`.github/workflows/docker-build.yml`)

On push to `main`:
1. Builds Docker image from `./backend`
2. Tags with `latest` only
3. Pushes to `ghcr.io/baseijs/geostreak`

(The workflow does **not** currently pass `APP_VERSION` or `GIT_SHA` as build args — so `__APP_VERSION__` in the HTML always resolves to `'dev'` in production. Visible versioning is handled by the hand-bumped marker in [`backend/public/index.html`](backend/public/index.html) — see "Version Marker" below.)

### Docker

The Dockerfile:
- Base: `node:20-alpine`
- Installs production deps
- Accepts `APP_VERSION` and `GIT_SHA` build args, sets them as env vars
- Exposes port 3000

### Production Deployment (Komodo)

- Komodo manages the production `docker-compose.yml` in a separate `docker-stacks` repo
- Database volume: `/docker/geostreak/database:/app/data` (outside the repo to survive reclones)
- Environment variables include `JWT_SECRET`, `MAPBOX_TOKEN`, `NODE_ENV=production`

### Known Deployment Gotchas

- **Komodo Reclone**: If enabled, wipes the repo directory on every deploy. Data volumes MUST be outside the repo path.
- **Image not updating**: `docker compose pull && docker compose up -d --force-recreate` is the reliable way to force a new image. Komodo's redeploy doesn't always pull the latest.
- **Verify deployments**: `docker inspect <container> --format '{{.Image}}'` against `docker images ghcr.io/baseijs/geostreak --digests` is the only reliable way to confirm which image is running.

## Development Workflow

Bas works from a Mac (restricted, no sudo) and a second machine, syncing via git:

```bash
cd ~/Downloads/geostreak && git add . && git commit -m "message" && git push
```

### Key Principles

- **Brainstorm before implementing** — don't jump ahead. Discuss the approach before writing code.
- **Always include both EN and NL translations** for any new user-facing string.
- **Extensible configs** — use config objects (like `LB_REGIONS`) for features that will grow over time.
- **Watch for scope creep** — Bas will call it out. Stay focused on what was asked.
- **DB schema discipline** — always verify `CREATE TABLE` statements include all expected columns. Silent failures from schema mismatches have caused bugs before.
- **Stale file awareness** — if working from files in context, they may be outdated. Check the actual current state before editing.
- **NL places are woonplaatsen, not gemeenten** — `nl-places.js` entries must have a real place name in `name`, not just the gemeente name. Some gemeente names match their main woonplaats (e.g., Amsterdam) and are fine. Others (e.g., Halderberge) are administrative mergers with no actual place by that name — those must not appear as `name` values.
- **ALWAYS bump the version marker on every commit** — see "Version Marker" below. Bas relies on this badge to confirm the new code is actually deployed; if you skip it, he has no way to tell stale-cache from undeployed from old-image.

## Common Tasks

### Adding a new region (e.g. Europe)

1. Add data array (like `NL_PLACES` but for European countries/cities)
2. Add entry to `LB_REGIONS` config
3. Add region option to `renderSetupRegions()` in the game setup modal
4. Add question type support (or reuse world question types)
5. Add difficulty filtering logic
6. Ensure all new strings are in both EN and NL

### Adding a new question type

1. Add the question builder function (e.g. `buildNewTypeQ`)
2. Add the answer handler in the appropriate submit function
3. Add it to the question type selection logic for the relevant mode/difficulty
4. Add translation strings for question text and feedback
5. If it needs admin toggles, add to settings (server defaults + allowed list + admin UI + frontend read)

### Adding a new admin setting

1. Add default value in server.js `DEFAULT_SETTINGS` object
2. Add to the `/api/settings` GET response (with the right type cast — `parseInt`, `=== '1'`, etc.)
3. Add to the `allowed` array in `/api/admin/settings` POST
4. Add the same default to the frontend `gameSettings` object literal in `index.html`. This matters: `fetchSettings()` does `gameSettings = {...gameSettings, ...data}` so frontend defaults survive as a fallback when the backend hasn't redeployed yet. Skipping this step caused the unlock locks to silently bypass on first deploy — `undefined || 0` made the threshold 0, which the lock check treats as "disabled".
5. Add UI control in the admin panel HTML (in the appropriate `<details>` section)
6. Wire up in `loadAdminSettings()` and `saveSettings()` on the frontend
7. Use `gameSettings.settingName` in game logic

### Making the admin command to set a user as admin

```bash
docker exec geostreak-geostreak-1 node -e "const db = require('better-sqlite3')('/app/data/geogame.db'); db.prepare('UPDATE users SET is_admin = 1 WHERE username = ?').run('Bas'); console.log('Done');"
```

## Version Marker

A single hand-bumped string in [`backend/public/index.html`](backend/public/index.html) (look for the `BUILD_MARKER` comment near the top of `<body>`) renders into a small badge in the bottom-right corner on every screen. This is the **only** reliable way Bas can tell which build of the code is actually running in his browser.

**Rule: every commit must bump this marker.** No exceptions — even doc-only or CSS-only commits. If you forget, Bas tests, sees the same badge, and assumes nothing deployed.

Format: `v<YYYY-MM-DD>-<short-kebab-tag>`
- Date: today's date (use the `currentDate` from your context, not your training cutoff).
- Tag: 1–4 kebab-case words describing the change. Keep it terse — it's a marker, not a changelog. Examples: `versioning`, `nl-province-rev`, `duel-rematch-fix`, `lock-icon-polish`.
- If you make multiple commits in one day, suffix with `-2`, `-3`, etc.: `v2026-05-18-versioning-2`.

There is **no** `/api/version` endpoint and CI does **not** inject a build number — earlier versions of this doc claimed both, but neither exists. If you ever wire them up, update this section.
