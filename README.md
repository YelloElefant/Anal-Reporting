# Anal-Reporting

A plug-and-play analytics middleware + dashboard for **Node.js/Express** apps.  
It captures request metadata (route, status, latency, IP, user-agent, etc.), batches it into PostgreSQL, and serves a built-in dashboard with charts and tables.

No extra worker or Redis required — one package does it all.

---

## Features

- 📈 **Traffic insights**: 30-day totals, hourly/daily breakdowns, top routes, and top IPs.
- ⚡ **Latency stats**: p50 / p95 / p99 response times.
- 👀 **Live request log**: recent requests with method, route, status, latency, and IP.
- 🔒 **Configurable IP handling**: full, CIDR-anonymized, or hashed.
- 🎨 **Modern dashboard UI**: responsive dark theme with auto-refresh, sorting, and filtering.
- 🛠 **Zero setup**: table auto-created in Postgres if missing.
- 🚀 **Drop-in usage**: one line in your `app.js`.

---

## Install

Clone or add the package to your project:

```bash
npm install ./anal-reporting
```

package.json:

```json
{
  "name": "my-app",
  "private": true,
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "@yelloelefant/anal-reporting": "file:./anal-reporting",
    "express": "^4.19.2",
    "pg": "^8.12.0"
  }
}
```

Dependencies:

- Node.js 18+
- PostgreSQL 13+

---

## Usage

In your Express app:

```js
const express = require("express");
const { enableAnalytics } = require("@yelloelefant/anal-reporting");

const app = express();

enableAnalytics(app, {
  databaseUrl: process.env.DATABASE_URL, // postgres://user:pass@host:5432/db
  dashboard: {
    bind: "0.0.0.0",
    port: 4319,
    basicAuth: { user: "admin", pass: "changeme" },
  },
  anonymizeIp: "none", // "none" | "cidr" | "hash"
});

app.set("trust proxy", true);
app.get("/", (_, res) => res.send("Hello with analytics!"));
app.listen(3000);
```

---

## Dashboard

- **Path**: available at `http://localhost:4319`
- **Endpoints**:

  - `/api/summary` → KPIs & latency
  - `/api/traffic?window=24 hours&bucket=hour`
  - `/api/top-routes`
  - `/api/top-ips`
  - `/api/recent`

---

## Database Schema

`web_analytics_events` is created automatically:

```sql
CREATE TABLE web_analytics_events (
  id BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  event_type TEXT NOT NULL,
  user_id TEXT NULL,
  route TEXT NULL,
  method TEXT NULL,
  status SMALLINT NULL,
  latency_ms INT NULL,
  ip_cidr TEXT NULL,
  ip_full TEXT NULL,
  user_agent TEXT NULL,
  meta JSONB NULL
);
```

---

## Environment Variables

- `DATABASE_URL` – Postgres connection string.
- `DASH_BIND` / `DASH_PORT` – dashboard bind address/port (default: `0.0.0.0:4319`).
- `DASH_USER` / `DASH_PASS` – enable HTTP Basic Auth.
- `ANONYMIZE_IP` – `"none"`, `"cidr"`, or `"hash"`.

---

## License

MIT © 2025 YelloElefant
