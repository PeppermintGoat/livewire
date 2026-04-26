/**
 * REST API layer for Cross-Claude MCP.
 *
 * Exposes the same message bus functionality as the MCP tools,
 * but via plain REST endpoints that any HTTP client can call —
 * ChatGPT Custom GPTs (Actions), Gemini, open-source agents, curl, etc.
 *
 * Mount: app.use("/api", createRestRouter(db))
 */

import { Router } from "express";
import { STALE_THRESHOLD_SECONDS } from "./tools.mjs";
import { normalizeChannelName } from "./db.mjs";

/**
 * @param {object} db - Database instance (SqliteDB or PostgresDB)
 * @returns {Router}
 */
export function createRestRouter(db) {
  const router = Router();
  router.use((req, res, next) => {
    // express.json() should already be applied, but ensure it
    if (req.is("application/json") && !req.body) {
      return res.status(400).json({ error: "Request body must be JSON" });
    }
    next();
  });

  // --- Instances ---

  router.post("/register", async (req, res, next) => {
    try {
      const { instance_id, description } = req.body;
      if (!instance_id) return res.status(400).json({ error: "instance_id is required" });
      await db.registerInstance(instance_id, description || null, null);
      res.json({ ok: true, instance_id });
    } catch (e) { next(e); }
  });

  router.get("/instances", async (req, res, next) => {
    try {
      await db.markStaleOffline(STALE_THRESHOLD_SECONDS);
      const instances = await db.listInstances();
      res.json({ instances });
    } catch (e) { next(e); }
  });

  // --- Channels ---

  router.post("/channels", async (req, res, next) => {
    try {
      const { name, description } = req.body;
      if (!name) return res.status(400).json({ error: "name is required" });
      const normalized = normalizeChannelName(name);
      if (!normalized) return res.status(400).json({ error: `Invalid channel name "${name}"` });
      await db.createChannel(normalized, description || null);
      res.json({ ok: true, channel: normalized });
    } catch (e) { next(e); }
  });

  router.get("/channels", async (req, res, next) => {
    try {
      const channels = await db.listChannelsWithActivity();
      res.json({ channels });
    } catch (e) { next(e); }
  });

  router.get("/channels/search", async (req, res, next) => {
    try {
      const { q } = req.query;
      if (!q) return res.status(400).json({ error: "q (query) parameter is required" });
      const channels = await db.findChannels(q);
      res.json({ channels });
    } catch (e) { next(e); }
  });

  // --- Messages ---

  // Rate limit: 8 messages per sender per 30 min window. System pings exempt.
  const RATE_LIMIT_MAX = 8;
  const RATE_LIMIT_WINDOW_MIN = 30;
  const RATE_LIMIT_EXEMPT = new Set(["__auth_check__"]);

  router.post("/messages", async (req, res, next) => {
    try {
      const { channel = "general", sender, content, message_type = "message", in_reply_to, created_at } = req.body;
      if (!sender) return res.status(400).json({ error: "sender is required" });
      if (!content) return res.status(400).json({ error: "content is required" });
      const validTypes = ["message", "request", "response", "status", "handoff", "done"];
      if (!validTypes.includes(message_type)) {
        return res.status(400).json({ error: `message_type must be one of: ${validTypes.join(", ")}` });
      }
      // Validate optional created_at — must parse as a real date
      if (created_at !== undefined && created_at !== null) {
        const ts = new Date(created_at);
        if (isNaN(ts.getTime())) {
          return res.status(400).json({ error: "created_at must be a valid ISO 8601 date string" });
        }
      }
      // Rate limit (skip for migration writes that pass created_at, and skip exempt senders)
      if (!RATE_LIMIT_EXEMPT.has(sender) && !created_at) {
        const sinceTime = new Date(Date.now() - RATE_LIMIT_WINDOW_MIN * 60 * 1000).toISOString();
        const recent = await db.countMessagesSince(sender, sinceTime);
        if (recent >= RATE_LIMIT_MAX) {
          return res.status(429).json({
            error: "rate_limited",
            message: `Sender "${sender}" sent ${recent} messages in the last ${RATE_LIMIT_WINDOW_MIN} min (limit: ${RATE_LIMIT_MAX}). Try again later.`,
            sender,
            recent_count: recent,
            limit: RATE_LIMIT_MAX,
            window_minutes: RATE_LIMIT_WINDOW_MIN
          });
        }
      }
      const normalized = normalizeChannelName(channel);
      if (!normalized) return res.status(400).json({ error: `Invalid channel name "${channel}"` });
      // Auto-create channel if it doesn't exist
      await db.createChannel(normalized, null);
      const id = await db.sendMessage(normalized, sender, content, message_type, in_reply_to || null, created_at || null);
      res.json({ ok: true, id: Number(id), channel: normalized, message_type });
    } catch (e) { next(e); }
  });

  router.delete("/channels/:name", async (req, res, next) => {
    try {
      const { name } = req.params;
      const normalized = normalizeChannelName(name);
      if (!normalized) return res.status(400).json({ error: `Invalid channel name "${name}"` });
      const deleted = await db.deleteChannel(normalized);
      if (!deleted) return res.status(404).json({ error: `Channel "${normalized}" not found` });
      res.json({ ok: true, deleted: normalized });
    } catch (e) { next(e); }
  });

  router.delete("/messages/:channel/:id", async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) return res.status(400).json({ error: "id must be a number" });
      const deleted = await db.deleteMessage(id);
      if (!deleted) return res.status(404).json({ error: `Message #${id} not found` });
      res.json({ ok: true, deleted: id });
    } catch (e) { next(e); }
  });

  router.get("/messages/:channel", async (req, res, next) => {
    try {
      const { channel } = req.params;
      const after_id = req.query.after_id ? parseInt(req.query.after_id) : undefined;
      const instance_id = req.query.instance_id;
      const limit = parseInt(req.query.limit) || 20;

      let messages;
      if (instance_id && after_id !== undefined) {
        messages = await db.getUnread(channel, after_id, instance_id);
      } else if (after_id !== undefined) {
        messages = await db.getMessagesSince(channel, after_id);
      } else {
        messages = await db.getMessages(channel, limit);
        messages.sort((a, b) => a.id - b.id);
      }

      const last_id = messages.length > 0 ? Number(messages[messages.length - 1].id) : null;
      res.json({ messages, last_id });
    } catch (e) { next(e); }
  });

  router.get("/messages/:channel/:id/replies", async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const parent = await db.getMessage(id);
      if (!parent) return res.status(404).json({ error: `Message #${id} not found` });
      const replies = await db.getReplies(id);
      res.json({ parent, replies });
    } catch (e) { next(e); }
  });

  router.get("/search", async (req, res, next) => {
    try {
      const { q } = req.query;
      if (!q) return res.status(400).json({ error: "q (query) parameter is required" });
      const limit = parseInt(req.query.limit) || 10;
      const messages = await db.searchMessages(q, limit);
      res.json({ messages });
    } catch (e) { next(e); }
  });

  // --- Shared Data ---

  router.post("/data", async (req, res, next) => {
    try {
      const { key, content, sender, description } = req.body;
      if (!key) return res.status(400).json({ error: "key is required" });
      if (!content) return res.status(400).json({ error: "content is required" });
      if (!sender) return res.status(400).json({ error: "sender is required" });
      await db.shareData(key, content, sender, description || null);
      const size_bytes = Buffer.byteLength(content);
      res.json({ ok: true, key, size_bytes });
    } catch (e) { next(e); }
  });

  router.get("/data", async (req, res, next) => {
    try {
      const items = await db.listSharedData();
      res.json({ items });
    } catch (e) { next(e); }
  });

  router.get("/data/:key", async (req, res, next) => {
    try {
      const data = await db.getSharedData(req.params.key);
      if (!data) return res.status(404).json({ error: `No shared data for key "${req.params.key}"` });
      res.json(data);
    } catch (e) { next(e); }
  });

  // --- Error handler ---

  router.use((err, req, res, _next) => {
    console.error("REST API error:", err);
    res.status(500).json({ error: "Internal server error" });
  });

  return router;
}
