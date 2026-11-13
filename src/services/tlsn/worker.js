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

/** The request, header block only, without the lines that carry a credential. */
function sentRanges(sent) {
  const end = headerEnd(sent);
  const ranges = [];
  let lineStart = 0;
  for (let i = 0; i < end; i++) {
    if (sent[i] !== 10) continue;
    const lower = new TextDecoder('latin1')
      .decode(sent.subarray(lineStart, i + 1))
      .toLowerCase();
    if (!SECRET_HEADERS.some((name) => lower.startsWith(name))) {
      ranges.push({ start: lineStart, end: i + 1 });
    }
    lineStart = i + 1;
  }
  if (lineStart < end) ranges.push({ start: lineStart, end });
  return merge(ranges);
}

/** The response: everything, headers only, or the lines matching a needle. */
function recvRanges(recv, reveal) {
  const mode = reveal?.mode || 'all';
  if (mode === 'all') return [{ start: 0, end: recv.length }];

  const end = headerEnd(recv);
  if (mode === 'headers') return [{ start: 0, end }];

  const needle = encoder.encode(String(reveal?.needle || ''));
  if (needle.length === 0) throw new Error('this reveal needs a search string');

  const ranges = [{ start: 0, end }];
  let found = 0;
  for (let i = 0; i + needle.length <= recv.length; i++) {
    let hit = true;
    for (let j = 0; j < needle.length; j++) {
      if (recv[i + j] !== needle[j]) {
        hit = false;
        break;
      }
    }
    if (!hit) continue;
    found += 1;
    // Publish the whole line the match sits on, so the revealed text is
    // readable rather than a fragment.
    let start = i;
    while (start > end && recv[start - 1] !== 10) start--;
    let stop = i + needle.length;
    while (stop < recv.length && recv[stop] !== 10) stop++;
    ranges.push({ start, end: Math.min(recv.length, stop + 1) });
    i = stop;
  }
  if (found === 0) {
    throw new Error(`the response does not contain ${JSON.stringify(String(reveal.needle))}`);
  }
  return merge(ranges);
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

    const sentReveal = sentRanges(sent);
    const recvReveal = recvRanges(received, reveal);
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
