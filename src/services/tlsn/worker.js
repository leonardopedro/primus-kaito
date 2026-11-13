// Hosts the WASM prover.
//
// `initialize()` primes rayon's pool by blocking on `Atomics.wait`, which a
// window's main thread refuses to do ("Atomics.wait cannot be called in this
// context"). A dedicated worker is allowed to block, and it can open the
// WebSocket to the notary itself, so the whole session lives here and the page
// only ever sees progress and the result.
//
// Copied to `build/tlsn/worker.js` next to the package it imports, so the
// import below is a plain relative module load — no bundler in the way.

import { WebSocketChannel } from './wsChannel.js';

const PACKAGE = './tlsn_wasm.js';

let ready = null;

async function load() {
  if (!ready) {
    ready = (async () => {
      const module = await import(PACKAGE);
      await module.default({ module_or_path: new URL('./tlsn_wasm_bg.wasm', import.meta.url) });
      await module.initialize(null, Math.max(2, Math.min(8, navigator.hardwareConcurrency || 2)));
      return module;
    })();
  }
  return ready;
}

const encoder = new TextEncoder();

// --- reveal -----------------------------------------------------------------
//
// A reveal names byte ranges of the transcript that the record publishes; every
// byte outside them is withheld. The digest pair is therefore taken over the
// SAME buffer the notary signs — the full transcript length with the withheld
// bytes zero-filled. That is not a detail: `/proxy/attestations/<id>` is keyed
// by those two digests, so hashing anything else (the full transcript, or just
// the revealed bytes) makes every selective session unfindable in the public
// listing even though the session itself verified.
//
// The request headers are the one part that must never be revealed wholesale:
// with cookies enabled they carry the user's session, and the record is served
// publicly at `/proxy/attestations`. Credential lines are dropped by name and
// the rest of the request line is kept, which is what an auditor needs to see
// (which method, which path).

const SECRET_HEADERS = ['cookie:', 'authorization:', 'proxy-authorization:'];

/** Index just past the `\r\n\r\n` that ends the header block, or the end. */
function headerEnd(bytes) {
  for (let i = 0; i + 3 < bytes.length; i++) {
    if (bytes[i] === 13 && bytes[i + 1] === 10 && bytes[i + 2] === 13 && bytes[i + 3] === 10) {
      return i + 4;
    }
  }
  return bytes.length;
}

function merge(ranges) {
  const sorted = ranges.filter((r) => r.end > r.start).sort((a, b) => a.start - b.start);
  const out = [];
  for (const range of sorted) {
    const last = out[out.length - 1];
    if (last && range.start <= last.end) {
      last.end = Math.max(last.end, range.end);
    } else {
      out.push({ ...range });
    }
  }
  return out;
}

/** The request header lines, each flagged when it carries a credential. */
function requestLines(sent) {
  const end = headerEnd(sent);
  const lines = [];
  let lineStart = 0;
  const push = (stop) => {
    const lower = new TextDecoder('latin1').decode(sent.subarray(lineStart, stop)).toLowerCase();
    lines.push({
      start: lineStart,
      end: stop,
      secret: SECRET_HEADERS.some((name) => lower.startsWith(name)),
    });
  };
  for (let i = 0; i < end; i++) {
    if (sent[i] !== 10) continue;
    push(i + 1);
    lineStart = i + 1;
  }
  if (lineStart < end) push(end);
  return lines;
}

/** The request, header block only, without the lines that carry a credential. */
function sentRanges(sent) {
  return merge(
    requestLines(sent)
      .filter((line) => !line.secret)
      .map(({ start, end }) => ({ start, end }))
  );
}

/** ASCII case folding, so `User-agent` finds `user-agent:` — header names are
 *  conventionally lowercase on the wire but nobody types them that way. */
function fold(byte) {
  return byte >= 65 && byte <= 90 ? byte + 32 : byte;
}

/**
 * The whole lines of `bytes` that contain `needle`, searched between
 * `from` and `to`, never extending a line above `floor`.
 *
 * The whole line is published rather than the fragment so the revealed text
 * reads as a header line or a body line instead of an orphaned substring.
 */
function needleLines(bytes, needle, { from = 0, to = bytes.length, floor = 0 } = {}) {
  const ranges = [];
  for (let i = from; i + needle.length <= to; i++) {
    let hit = true;
    for (let j = 0; j < needle.length; j++) {
      if (fold(bytes[i + j]) !== fold(needle[j])) {
        hit = false;
        break;
      }
    }
    if (!hit) continue;
    let start = i;
    while (start > floor && bytes[start - 1] !== 10) start--;
    let stop = i + needle.length;
    while (stop < bytes.length && bytes[stop] !== 10) stop++;
    ranges.push({ start, end: Math.min(bytes.length, stop + 1) });
    i = stop;
  }
  return ranges;
}

/**
 * What to disclose: the request header block (minus credentials), plus the
 * response — all of it, its headers only, or the lines matching a needle in
 * EITHER direction.
 *
 * Searching the request too is what makes a needle like `User-agent` usable,
 * since a request header never appears in the response. A match on a withheld
 * request line (cookie/authorization) is reported but never disclosed, and a
 * needle that misses the response is called out as a warning rather than
 * silently succeeding on request evidence alone.
 */
function revealRanges(sent, recv, reveal) {
  const mode = reveal?.mode || 'all';
  const sentReveal = sentRanges(sent);
  const notes = [];
  const headerLimit = headerEnd(recv);

  if (mode === 'all') {
    return { sent: sentReveal, recv: [{ start: 0, end: recv.length }], notes };
  }
  if (mode === 'headers') {
    return { sent: sentReveal, recv: [{ start: 0, end: headerLimit }], notes };
  }

  const needle = encoder.encode(String(reveal?.needle || ''));
  if (needle.length === 0) throw new Error('this reveal needs a search string');
  const quoted = JSON.stringify(String(reveal.needle));

  const requestHits = needleLines(sent, needle, { to: headerEnd(sent) });
  const lines = requestLines(sent);
  const secretHits = requestHits.filter((hit) =>
    lines.some((line) => line.secret && hit.start >= line.start && hit.start < line.end)
  );
  const responseHits = needleLines(recv, needle, { from: headerLimit, floor: headerLimit });

  if (responseHits.length === 0) {
    notes.push(`warning: the response does not contain ${quoted}`);
    if (requestHits.length > secretHits.length) {
      notes.push(`it matched the request only — that is all this record discloses for it`);
    }
  }
  if (secretHits.length > 0) {
    notes.push(`a matching request line is a credential (cookie/authorization) and stays withheld`);
  }
  if (responseHits.length === 0 && requestHits.length === 0) {
    throw new Error(`neither the request nor the response contains ${quoted}`);
  }

  return {
    sent: sentReveal,
    recv: merge([{ start: 0, end: headerLimit }, ...responseHits]),
    notes,
  };
}

/** The transcript as the notary signs it: same length, withheld bytes zeroed. */
function maskRanges(bytes, ranges) {
  const out = new Uint8Array(bytes.length);
  for (const r of ranges) out.set(bytes.subarray(r.start, r.end), r.start);
  return out;
}

function headerMap(headers) {
  const map = new Map();
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || value === null) continue;
    map.set(name, Array.from(encoder.encode(String(value))));
  }
  return map;
}

async function digest(bytes) {
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function run({ notaryUrl, serverName, path, headers, cookie, maxSent, maxRecv, reveal }) {
  const wasm = await load();

  const requestHeaders = {
    // The relay dials the target by name, but the edge in front of it still
    // routes on Host: without it Fastly answers 421 "Requested host does not
    // match any Subject Alternative Name".
    host: serverName,
    accept: '*/*',
    'user-agent': navigator.userAgent,
    connection: 'close',
    ...headers,
  };
  if (cookie) requestHeaders.cookie = cookie;

  const channel = new WebSocketChannel(notaryUrl);
  await channel.open();

  const prover = new wasm.Prover({
    server_name: serverName,
    // Proxy mode: the notary dials the target and relays the TLS bytes, so the
    // browser never talks to the target (no CORS, no second session).
    mode: 'Proxy',
    max_sent_data: maxSent,
    max_recv_data: maxRecv,
    network: 'Bandwidth',
  });
  prover.set_progress_callback((event) => {
    self.postMessage({ type: 'progress', event });
  });

  try {
    await prover.setup(channel);
    const response = await prover.send_request(null, {
      uri: path,
      method: 'GET',
      headers: headerMap(requestHeaders),
    });
    const transcript = prover.transcript();
    const sent = new Uint8Array(transcript.sent);
    const received = new Uint8Array(transcript.recv);

    const { sent: sentReveal, recv: recvReveal, notes } = revealRanges(sent, received, reveal);
    await prover.reveal({ sent: sentReveal, recv: recvReveal, server_identity: true });
    await prover.finish();

    const revealedBytes = (ranges) => ranges.reduce((n, r) => n + (r.end - r.start), 0);
    return {
      status: response.status,
      sentBytes: sent.length,
      receivedBytes: received.length,
      sentSha256: await digest(maskRanges(sent, sentReveal)),
      receivedSha256: await digest(maskRanges(received, recvReveal)),
      recvText: new TextDecoder().decode(received),
      notes,
      revealed: {
        sentRanges: sentReveal.length,
        recvRanges: recvReveal.length,
        sentBytes: revealedBytes(sentReveal),
        recvBytes: revealedBytes(recvReveal),
      },
    };
  } finally {
    channel.close();
  }
}

self.addEventListener('message', async (event) => {
  const message = event.data;
  if (message?.type !== 'run') return;
  try {
    const result = await run(message.config);
    self.postMessage({ type: 'done', result });
  } catch (error) {
    self.postMessage({
      type: 'error',
      message: error?.message || String(error),
      stack: error?.stack,
    });
  }
});
