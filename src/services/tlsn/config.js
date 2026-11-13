// Where the notary lives and what it will relay.
//
// The notary answers the TLSNotary protocol on a TCP port (8443 by default),
// which a browser cannot open. The same listener accepts a WebSocket upgrade,
// so the extension speaks `ws://host:8443/` — or `wss://` when the operator
// fronts the notary with a TLS terminator. Set `notaryUrl` at runtime from the
// Notary page; this is only the default.

// Host IP, not the domain name, on purpose: the notary speaks PLAINTEXT
// WebSocket, and any plaintext HTTP request whose Host header is an unfiled
// mainland domain is answered by Alibaba's ICP interceptor (HTTP 403, Server:
// Beaver) before it ever reaches the enclave — the upgrade dies there. With the
// IP as Host the handshake completes (101) and the notary bridges it like any
// other session. The HTTPS origin below keeps using the domain, so attestation
// fetches and certificate validation are unaffected.
export const NOTARY_URL = 'ws://101.200.178.251:8443/';

// The origin that publishes the attestation list. The signed record is fetched
// from here with the digest pair the prover computed, and this origin is also
// where the notary's public description lives (GET /notary).
export const NOTARY_ORIGIN = 'https://login.airma.de';

// Read by the Notary page as the starting point. The notary itself is the
// authority on what it will relay (`relay_targets`); this list only keeps the
// form honest about the hosts an operator has already pinned.
export const KNOWN_HOSTS = [
  'www.sandbox.paypal.com',
  'sandbox.paypal.com',
  'api-m.sandbox.paypal.com',
  'api-m.paypal.com',
];

// Path used when the page opens on a host: `/robots.txt` answers with a small,
// stable body on every PayPal sandbox host, which makes it the cheapest target
// to prove the whole path works before asking for a page.
export const DEFAULT_PATH = '/robots.txt';

// Upper bounds handed to the prover. They size what the prover will accept from
// the target, not what the notary relays; a page that exceeds them is refused
// before the MPC spends time on it.
export const MAX_SENT_BYTES = 16 * 1024;
export const MAX_RECV_BYTES = 1024 * 1024;
