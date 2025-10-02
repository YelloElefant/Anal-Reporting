"use strict";
const { Pool } = require("pg");
const http = require("http");

function tableSql(table) {
  return `
  CREATE TABLE IF NOT EXISTS ${table} (
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
  CREATE INDEX IF NOT EXISTS idx_${table}_time ON ${table} (occurred_at DESC);
  CREATE INDEX IF NOT EXISTS idx_${table}_type ON ${table} (event_type);
  CREATE INDEX IF NOT EXISTS idx_${table}_route ON ${table} (route);
  CREATE INDEX IF NOT EXISTS idx_${table}_status ON ${table} (status);
  `;
}

function makeAnonymizer(mode, hashSalt = "") {
  if (mode === "none") return (ip) => ip || null;
  if (mode === "hash") {
    const crypto = require("crypto");
    return (ip) =>
      ip
        ? crypto
            .createHash("sha256")
            .update(hashSalt + ip)
            .digest("hex")
            .slice(0, 16)
        : null;
  }
  // default: 'cidr'
  return (ip) => {
    if (!ip) return null;
    if (ip.includes(":")) return ip.split(":").slice(0, 3).join(":") + "::"; // IPv6 /48
    const p = ip.split(".");
    if (p.length !== 4) return ip;
    p[3] = "0";
    return p.join("."); // IPv4 /24
  };
}

function defaultNormalizeRoute(req) {
  return (req.route && req.route.path) || req.path;
}
function defaultGetUserId(req) {
  return (req.user && req.user.id) || null;
}
function defaultSample() {
  return true;
}

function enableAnalytics(app, opts = {}) {
  const table = opts.table || "web_analytics_events";
  const batchSize = Number(opts.batch || 500);
  const intervalMs = Number(opts.intervalMs || 2000);
  const anonymizeIp = makeAnonymizer(
    opts.anonymizeIp || "cidr",
    opts.hashSalt || ""
  );
  const normalizeRoute = opts.normalizeRoute || defaultNormalizeRoute;
  const getUserId = opts.getUserId || defaultGetUserId;
  const sample = opts.sample || defaultSample;
  const redactPaths = opts.redactPaths || [/\.(css|js|png|jpg|svg|woff2?)$/i];

  if (!opts.databaseUrl) {
    throw new Error("enableAnalytics: databaseUrl is required");
  }

  const pool = new Pool({ connectionString: opts.databaseUrl });

  // 1) Ensure table exists
  pool.query(tableSql(table)).catch((err) => {
    console.error("[analytics] failed to ensure table:", err.message);
  });

  // 2) In-memory queue + background batch inserter
  const queue = [];
  let draining = false;
  async function drain() {
    if (draining || queue.length === 0) return;
    draining = true;
    try {
      const items = queue.splice(0, batchSize);
      const values = [];
      const params = [];
      let i = 1;
      for (const e of items) {
        values.push(
          `($${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++})`
        );
        params.push(
          e.event_type,
          e.occurred_at,
          e.user_id,
          e.route,
          e.method,
          e.status,
          e.latency_ms,
          e.ip_cidr,
          e.ip_full,
          e.user_agent,
          e.meta || null
        );
      }
      const sql = `
        INSERT INTO ${table}
        (event_type, occurred_at, user_id, route, method, status, latency_ms, ip_cidr, ip_full, user_agent, meta)
        VALUES ${values.join(",")}
      `;
      await pool.query(sql, params);
    } catch (err) {
      console.error("[analytics] batch insert failed:", err.message);
      // best-effort: dropped on error; you can add a file fallback if desired
    } finally {
      draining = false;
    }
  }
  setInterval(drain, intervalMs).unref();

  // 3) Middleware (non-blocking)
  app.use((req, res, next) => {
    if (redactPaths.some((r) => r.test(req.path))) return next();
    const start = process.hrtime.bigint();
    res.on("finish", () => {
      try {
        if (!sample(req, res)) return;
        const end = process.hrtime.bigint();
        const latencyMs = Math.round(Number(end - start) / 1e6);
        const xfwd = Array.isArray(req.headers["x-forwarded-for"])
          ? req.headers["x-forwarded-for"][0]
          : req.headers["x-forwarded-for"] || "";
        const ip = (xfwd || req.ip || "").split(",")[0].trim();

        queue.push({
          event_type: "request",
          occurred_at: new Date().toISOString(),
          user_id: getUserId(req),
          route: normalizeRoute(req),
          method: req.method,
          status: res.statusCode,
          latency_ms: latencyMs,
          ip_cidr: anonymizeIp(ip),
          ip_full: opts.anonymizeIp === "none" ? ip || null : null,
          user_agent: req.get && req.get("user-agent"),
          meta: {
            url: req.originalUrl,
            ref: (req.get && req.get("referer")) || null,
            hostname: process.env.HOSTNAME || null,
          },
        });

        if (queue.length >= batchSize) drain();
      } catch (e) {
        // never throw
      }
    });
    next();
  });

  // 4) Optional embedded dashboard (no extra container)
  if (opts.dashboard) {
    const express = require("express");
    const dash = express();
    const bind = opts.dashboard.bind || "127.0.0.1";
    const port = Number(opts.dashboard.port || 4319);
    const basic = opts.dashboard.basicAuth;

    // simple basic-auth
    if (basic && basic.user) {
      dash.use((req, res, next) => {
        const hdr = req.headers.authorization || "";
        if (!hdr.startsWith("Basic ")) {
          res.set("WWW-Authenticate", "Basic");
          return res.status(401).send("Auth required");
        }
        const [u, p] = Buffer.from(hdr.slice(6), "base64")
          .toString("utf8")
          .split(":", 2);
        if (u === basic.user && p === basic.pass) return next();
        res.set("WWW-Authenticate", "Basic");
        return res.status(401).send("Bad credentials");
      });
    }

    // API
    dash.get("/api/summary", async (_, res) => {
      try {
        const [
          {
            rows: [{ count: total }],
          },
          { rows: statuses },
          {
            rows: [lat],
          },
        ] = await Promise.all([
          pool.query(
            `SELECT COUNT(*)::int FROM ${table} WHERE occurred_at > now() - interval '30 days'`
          ),
          pool.query(
            `SELECT status, COUNT(*)::int AS c FROM ${table} WHERE occurred_at > now() - interval '7 days' GROUP BY status ORDER BY c DESC`
          ),
          pool.query(`SELECT
                        percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms) AS p50,
                        percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95,
                        percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms) AS p99
                      FROM ${table}
                      WHERE occurred_at > now() - interval '24 hours'`),
        ]);
        res.json({ total_30d: total, statuses, latency: lat });
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });

    dash.get("/api/traffic", async (req, res) => {
      const window = req.query.window || "24 hours";
      const bucket = req.query.bucket || "hour";
      try {
        const q = await pool.query(
          `SELECT date_trunc($1, occurred_at) AS t, COUNT(*)::int AS c
           FROM ${table}
           WHERE occurred_at > now() - ($2)::interval
           GROUP BY 1 ORDER BY 1`,
          [bucket, window]
        );
        res.json(q.rows);
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });

    dash.get("/api/top-routes", async (_, res) => {
      try {
        const q = await pool.query(
          `SELECT route, COUNT(*)::int AS c
           FROM ${table}
           WHERE occurred_at > now() - interval '24 hours' AND route IS NOT NULL
           GROUP BY 1 ORDER BY 2 DESC LIMIT 50`
        );
        res.json(q.rows);
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });

    dash.get("/api/top-ips", async (_, res) => {
      try {
        const q = await pool.query(
          `SELECT COALESCE(ip_full, ip_cidr) AS ip, COUNT(*)::int AS c
           FROM ${table}
           WHERE occurred_at > now() - interval '24 hours'
           GROUP BY 1 ORDER BY 2 DESC LIMIT 50`
        );
        res.json(q.rows);
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });

    dash.get("/api/recent", async (_, res) => {
      try {
        const q = await pool.query(
          `SELECT occurred_at, method, route, status, latency_ms, ip_cidr, ip_full, user_agent
           FROM ${table}
           ORDER BY occurred_at DESC
           LIMIT 200`
        );
        res.json(q.rows);
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });

    // Minimal UI send public/index.html
    dash.use(express.static(__dirname + "/public"));
    dash.get("/", (_, res) => res.sendFile(__dirname + "/public/index.html"));

    const srv = http.createServer(dash);
    srv.listen(port, bind, () =>
      console.log(`[analytics] dashboard on http://${bind}:${port}`)
    );
  }

  console.log(
    "[analytics] enabled (table=%s, batch=%s, intervalMs=%s)",
    table,
    batchSize,
    intervalMs
  );
  return {
    stop: async () => {
      await pool.end();
    },
  };
}

module.exports = { enableAnalytics };
