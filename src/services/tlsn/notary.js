// The browser side of a notarised session.
//
// Two things make this work without a CLI:
//
//  * The prover is tlsn's WASM package, built for `--target web` and loaded as
//    a plain ES module from the extension's own files. It runs in a dedicated
//    worker (`worker.js`) because its `initialize()` blocks on `Atomics.wait`,
//    which the main thread of a window is not allowed to do.
//  * The notary's session port accepts a WebSocket upgrade next to the raw
//    TLSNotary protocol, so the worker — which can open sockets a page cannot —
//    reaches it with a normal `new WebSocket(...)`.
//
// Nothing about the page the user is browsing is modified: the prover opens its
// own TLS connection to the target through the notary, and the cookies handed
// to it are read from the browser's cookie store, not from the page.

import {
  DEFAULT_PATH,
  MAX_RECV_BYTES,
  MAX_SENT_BYTES,
  NOTARY_ORIGIN,
  NOTARY_URL,
} from './config';

const WORKER_URL = 'tlsn/worker.js';

/**
 * Reads the browser's cookies that would be sent to a host.
 *
 * The query is by `url`, not by `domain`: a site's cookies usually live on a
 * parent domain (`Domain=.paypal.com`), and a `domain: 'www.sandbox.paypal.com'`
 * filter only matches cookies whose own domain is that exact host — it would
 * find nothing on a real site. A `url` query answers the question the request
 * asks: which cookies does the browser attach to this request.
 *
 * `chrome.cookies` needs host access for the URL; the manifest grants the
 * PayPal hosts. A refusal is not fatal: the session is still notarised, it just
 * is not logged in, so the caller is told which happened instead of the whole
 * flow failing.
 */
export async function cookiesFor(host) {
  try {
    const cookies = await chrome.cookies.getAll({ url: `https://${host}/` });
    if (!cookies || cookies.length === 0) return { header: '', count: 0 };
    return {
      header: cookies.map((c) => `${c.name}=${c.value}`).join('; '),
      count: cookies.length,
    };
  } catch (error) {
    return { header: '', count: 0, error: error?.message || String(error) };
  }
}

/**
 * Runs one notarised session in the prover worker.
 *
 * @param {object} options
 * @param {string} options.serverName host whose certificate the notary relays
 * @param {string} [options.path] request path, default `/robots.txt`
 * @param {object} [options.headers] extra request headers
 * @param {string} [options.cookie] cookie header value
 * @param {string} [options.notaryUrl] WebSocket URL of the notary
 * @param {{mode: 'all'|'headers'|'match', needle?: string}} [options.reveal] what the record discloses
 * @param {(event: {step: string, progress: number, message: string}) => void} [options.onProgress]
 * @returns {Promise<{status, sentBytes, receivedBytes, sentSha256, receivedSha256, recvText, revealed}>}
 */
export function notarize({
  serverName,
  path = DEFAULT_PATH,
  headers = {},
  cookie = '',
  notaryUrl = NOTARY_URL,
  reveal = { mode: 'all' },
  onProgress,
}) {
  const worker = new Worker(chrome.runtime.getURL(WORKER_URL), { type: 'module' });

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      worker.terminate();
      fn(value);
    };

    worker.addEventListener('message', (event) => {
      const message = event.data;
      if (message?.type === 'progress') {
        if (onProgress) onProgress(message.event);
      } else if (message?.type === 'done') {
        finish(resolve, message.result);
      } else if (message?.type === 'error') {
        finish(reject, new Error(message.message));
      }
    });
    worker.addEventListener('error', (event) => {
      finish(reject, new Error(event.message || 'the prover worker failed to start'));
    });

    worker.postMessage({
      type: 'run',
      config: {
        notaryUrl,
        serverName,
        path,
        headers,
        cookie,
        maxSent: MAX_SENT_BYTES,
        maxRecv: MAX_RECV_BYTES,
        reveal,
      },
    });
  });
}

/**
 * Finds the signed record this session produced.
 *
 * The list publishes ids and fingerprints only, never transcripts, so the way
 * back to a record is the digest pair the prover is the only party to have
 * computed: try each recent id with the pair and take the one that answers.
 */
export async function findAttestation(
  { sentSha256, receivedSha256 },
  origin = NOTARY_ORIGIN
) {
  const base = origin.replace(/\/$/, '');
  const list = await fetch(`${base}/proxy/attestations`, { cache: 'no-store' });
  if (!list.ok) throw new Error(`the origin answered ${list.status} for the session list`);
  const body = await list.json();
  const ids = Array.isArray(body.sessions)
    ? body.sessions.map((row) => row.session_id).filter(Boolean)
    : [];
  for (const id of ids.slice().reverse()) {
    const url = `${base}/proxy/attestations/${id}?sent_sha256=${sentSha256}&received_sha256=${receivedSha256}`;
    const res = await fetch(url, { cache: 'no-store' });
    if (res.ok) return { id, url, record: await res.json() };
  }
  throw new Error(
    `the origin lists ${ids.length} session(s) but none accepts this transcript — the notary records a session only after it verifies`
  );
}
