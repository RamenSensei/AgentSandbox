/*
 * AgentKernel observability UI.
 *
 * Single-file vanilla JS app. No dependencies, no build step, works from
 * file://. Organization:
 *   1. Embedded demo data (mirrors demo-data.json, the canonical copy)
 *   2. App state and persistence
 *   3. Data loading (demo + live API)
 *   4. Small utilities (formatting, escaping, id/hash helpers)
 *   5. Renderers: timeline, branch graph, policy, receipts
 *   6. Header wiring and boot
 */

"use strict";

/* ------------------------------------------------------------------ */
/* 1. Embedded demo data                                               */
/*                                                                     */
/* This constant mirrors ui/demo-data.json byte-for-byte (see README). */
/* It exists because fetch() of a local JSON file is blocked on        */
/* file:// in several browsers; the app tries fetch first and falls    */
/* back to this.                                                       */
/* ------------------------------------------------------------------ */
