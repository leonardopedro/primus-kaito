// The Notary page: a form, a log, and the resulting record.
//
// This is a plain extension page rather than a React view because it is the
// only surface that has to outlive the popup and hold a session open across a
// multi-second MPC — and because it needs no state beyond the DOM.

import {
  DEFAULT_PATH,
  KNOWN_HOSTS,
  NOTARY_ORIGIN,
  NOTARY_URL,
} from '../../services/tlsn/config';
import { cookiesFor, findAttestation, notarize } from '../../services/tlsn/notary';

const el = (id) => document.getElementById(id);
const form = el('form');
const hostInput = el('host');
const pathInput = el('path');
const notaryInput = el('notary');
const cookieInput = el('useCookies');
const revealInput = el('reveal');
const needleInput = el('needle');
const runButton = el('run');
const logEl = el('log');
const resultEl = el('result');

function log(message) {
  const line = document.createElement('div');
  line.textContent = message;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

const STEP_LABELS = {
  SetupVerifier: 'setting up the verifier',
  SetupProver: 'setting up the prover',
  SendingRequest: 'sending the request',
  SendingRequestData: 'exchanging the request',
  ReceivingResponse: 'receiving the response',
  Reveal: 'revealing the transcript',
  Finalizing: 'closing the session',
};

function progress(event) {
  const step = event?.step || 'Working';
  const label = STEP_LABELS[step] || String(step);
  const percent = typeof event?.progress === 'number' ? Math.round(event.progress * 100) : null;
  log(`${percent === null ? label : `${label} — ${percent}%`}`);
}

function showResult({ ok, title, rows, link, body }) {
  resultEl.hidden = false;
  const titleEl = el('resultTitle');
  titleEl.textContent = title;
  titleEl.className = ok ? 'status-ok' : 'status-bad';

  const dl = el('resultBody');
  dl.textContent = '';
  for (const [name, value] of rows) {
    const dt = document.createElement('dt');
    dt.textContent = name;
    const dd = document.createElement('dd');
    dd.textContent = value;
    dl.append(dt, dd);
  }

  const linkEl = el('resultLink');
  linkEl.textContent = '';
  if (link) {
    const a = document.createElement('a');
    a.href = link.href;
    a.target = '_blank';
    a.rel = 'noopener';
    a.textContent = link.text;
    linkEl.appendChild(a);
  }

  const details = resultEl.querySelector('details');
  if (body) {
    el('responseText').textContent = body;
    details.hidden = false;
  } else {
    details.hidden = true;
  }
}

async function currentTabHost() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return null;
    const url = new URL(tab.url);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return url.host;
  } catch {
    return null;
  }
}

// The search field only means something for the matching reveal, so it is
// disabled otherwise — an enabled box that silently does nothing is worse than
// no box.
revealInput.addEventListener('change', () => {
  const matching = revealInput.value === 'match';
  needleInput.disabled = !matching;
  if (matching) needleInput.focus();
});

function revealChoice() {
  const mode = revealInput.value;
  if (mode === 'match') {
    const needle = needleInput.value;
    if (!needle) throw new Error('type the text the record should disclose');
    return { mode, needle };
  }
  return { mode };
}

async function init() {
  const tabHost = await currentTabHost();
  hostInput.value = tabHost || KNOWN_HOSTS[0];
  pathInput.value = DEFAULT_PATH;
  notaryInput.value = NOTARY_URL;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const host = hostInput.value.trim();
  const path = pathInput.value.trim() || DEFAULT_PATH;
  if (!host) return;

  logEl.textContent = '';
  resultEl.hidden = true;
  runButton.disabled = true;

  try {
    let cookie = '';
    if (cookieInput.checked) {
      const result = await cookiesFor(host);
      if (result.error) {
        log(`cookies unavailable (${result.error}) — continuing without them`);
      } else if (result.count > 0) {
        log(`sending ${result.count} cookie(s) for ${host}`);
        cookie = result.header;
      } else {
        log(`no cookies for ${host} — the request will be anonymous`);
      }
    }

    const session = await notarize({
      serverName: host,
      path,
      cookie,
      notaryUrl: notaryInput.value.trim() || NOTARY_URL,
      reveal: revealChoice(),
      onProgress: progress,
    });

    log(`notarised ${session.sentBytes} byte(s) sent, ${session.receivedBytes} byte(s) received`);
    log(
      `revealed ${session.revealed.sentBytes} request and ${session.revealed.recvBytes} response byte(s)`
    );

    const rows = [
      ['status', String(session.status)],
      ['sent', `${session.sentBytes} bytes`],
      ['received', `${session.receivedBytes} bytes`],
      ['revealed', `${session.revealed.sentBytes} + ${session.revealed.recvBytes} bytes`],
      ['sent_sha256', session.sentSha256],
      ['received_sha256', session.receivedSha256],
    ];

    let link = null;
    try {
      log('looking up the signed record');
      const found = await findAttestation(session, NOTARY_ORIGIN);
      rows.push(['record', found.id]);
      link = { href: found.url, text: 'Download the attestation' };
      log('signed record found');
    } catch (error) {
      rows.push(['record', `not found yet — ${error.message}`]);
      log(`signed record: ${error.message}`);
    }

    showResult({ ok: true, title: 'Session notarised', rows, link, body: session.recvText });
  } catch (error) {
    log(`failed: ${error?.message || error}`);
    showResult({
      ok: false,
      title: 'Could not notarise this session',
      rows: [['host', host], ['error', String(error?.message || error)]],
    });
  } finally {
    runButton.disabled = false;
  }
});

init();
