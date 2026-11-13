// A TLSNotary IoChannel over a WebSocket.
//
// tlsn's WASM prover takes its verifier transport from JavaScript as an object
// with `read()`, `write()`, `close()` and `unread()`. A browser cannot open a
// raw TCP socket, so the notary's session port also accepts a WebSocket upgrade
// and this class is the other half of that bridge: binary frames in, bytes out.
//
// The protocol does not care about framing, so this is a byte pipe, not a
// message protocol: frames are concatenated on the way in and split at whatever
// boundary the read size asks for. That is what makes `unread()` (which the
// prover uses to push back over-read bytes) a simple queue operation.

const HIGH_WATER = 4 * 1024 * 1024;

export class WebSocketChannel {
  /**
   * @param {string} url `ws://host:8443/` or `wss://…` behind a TLS terminator
   */
  constructor(url) {
    this.url = url;
    this.socket = null;
    this.queue = [];
    this.waiter = null;
    this.closed = false;
    this.failure = null;
  }

  /// Opens the socket. Rejects only if it never opened: a later close is EOF,
  /// which is what the protocol expects when the notary ends the session.
  open() {
    return new Promise((resolve, reject) => {
      let opened = false;
      let socket;
      try {
        socket = new WebSocket(this.url);
      } catch (e) {
        reject(new Error(`notary address is not a WebSocket URL: ${e.message}`));
        return;
      }
      socket.binaryType = 'arraybuffer';
      this.socket = socket;

      socket.onopen = () => {
        opened = true;
        resolve();
      };
      socket.onmessage = (event) => {
        const data = event.data;
        if (typeof data === 'string') return; // this transport is bytes only
        this.push(new Uint8Array(data));
      };
      socket.onerror = () => {
        this.failure = 'the connection to the notary failed';
        if (!opened) reject(new Error(this.failure));
      };
      socket.onclose = (event) => {
        if (!opened) {
          reject(
            new Error(
              `the notary closed the connection before it opened (code ${event.code})`
            )
          );
          return;
        }
        this.closed = true;
        this.release();
      };
    });
  }

  push(chunk) {
    if (chunk.length === 0) return;
    this.queue.push(chunk);
    this.release();
  }

  /// Hands the first queued chunk to a waiting read, or ends it on EOF.
  release() {
    if (!this.waiter) return;
    const next = this.queue.shift();
    if (next) {
      const resolve = this.waiter;
      this.waiter = null;
      resolve(next);
    } else if (this.closed) {
      const resolve = this.waiter;
      this.waiter = null;
      resolve(null);
    }
  }

  read() {
    const next = this.queue.shift();
    if (next) return Promise.resolve(next);
    if (this.closed) return Promise.resolve(null);
    return new Promise((resolve) => {
      this.waiter = resolve;
    });
  }

  async write(data) {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error('cannot write to a closed notary connection');
    }
    this.socket.send(data);
    // Let the socket drain rather than queueing the whole MPC in memory.
    while (this.socket.bufferedAmount > HIGH_WATER && !this.closed) {
      await new Promise((r) => setTimeout(r, 5));
    }
  }

  close() {
    this.closed = true;
    try {
      this.socket?.close();
    } catch {}
    this.release();
  }

  unread(data) {
    if (!data || data.length === 0) return;
    this.queue.unshift(data instanceof Uint8Array ? data : new Uint8Array(data));
    this.release();
  }
}
