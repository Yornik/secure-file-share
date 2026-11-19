/* Share retrieval: the ciphertext streams down, this page decrypts it with
   the key from the URL fragment — which the browser never sends to the
   server — and assembles the file locally. */

"use strict";

const decoder = new TextDecoder();

function $(id) {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error("missing element " + id);
  }
  return element;
}

function showError(message) {
  $("download-box").hidden = true;
  $("warn").hidden = true;
  $("state").hidden = true;
  const box = $("error");
  box.textContent = message;
  box.hidden = false;
}

function showProgress(label, fraction) {
  $("progress").hidden = false;
  $("progress-bar").style.width = Math.round(fraction * 100) + "%";
  $("progress-label").textContent = label;
}

function humanSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  const units = ["KiB", "MiB", "GiB"];
  let value = bytes;
  let unit = -1;
  do {
    value /= 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  return value.toFixed(value >= 10 ? 0 : 1) + " " + units[unit];
}

function keyFromFragment() {
  const hash = location.hash;
  if (!hash.startsWith("#key=")) {
    return null;
  }
  const encoded = hash.slice(5);
  const normalized = encoded
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(encoded.length + ((4 - (encoded.length % 4)) % 4), "=");
  try {
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
}

/* Reads exactly n bytes from the response stream, holding at most the
   current chunk plus n in memory. */
function makeTaker(response) {
  const reader = response.body.getReader();
  const queue = [];
  let queued = 0;
  return {
    async take(n) {
      while (queued < n) {
        const { done, value } = await reader.read();
        if (done) {
          return null;
        }
        queue.push(value);
        queued += value.length;
      }
      const out = new Uint8Array(n);
      let filled = 0;
      while (filled < n) {
        const head = queue[0];
        const need = n - filled;
        if (head.length <= need) {
          out.set(head, filled);
          filled += head.length;
          queue.shift();
        } else {
          out.set(head.subarray(0, need), filled);
          queue[0] = head.subarray(need);
          filled = need;
        }
      }
      queued -= n;
      return out;
    },
  };
}

async function fetchMeta(id) {
  const response = await fetch("/s/" + id + "/meta");
  if (response.status === 404) {
    return { gone: "This share does not exist. Check the link for typos." };
  }
  if (response.status === 410) {
    return { gone: "This share has expired or was already burned." };
  }
  if (!response.ok) {
    return { gone: "The server answered " + response.status + "." };
  }
  return response.json();
}

async function download(id, keyBytes) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    "AES-GCM",
    false,
    ["decrypt"],
  );

  const response = await fetch("/s/" + id + "/blob");
  if (response.status === 404) {
    throw new Error("This share does not exist.");
  }
  if (response.status === 410) {
    throw new Error("This share has expired or was already burned.");
  }
  if (!response.ok) {
    throw new Error("The server answered " + response.status + ".");
  }

  const total = Number(response.headers.get("Content-Length") || 0);
  const take = makeTaker(response);
  const parts = [];
  let received = 0;
  let meta = null;

  for (;;) {
    const prefix = await take.take(4);
    if (prefix === null) {
      break;
    }
    const length =
      (prefix[0] << 24) | (prefix[1] << 16) | (prefix[2] << 8) | prefix[3];
    if (length < 28) {
      throw new Error("the stream is malformed");
    }
    const frame = await take.take(length);
    if (frame === null) {
      throw new Error("the stream ended early");
    }
    received += 4 + length;
    if (total > 0) {
      showProgress("Decrypting\u2026", received / total);
    }
    let plain;
    try {
      plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: frame.subarray(0, 12) },
        cryptoKey,
        frame.subarray(12),
      );
    } catch {
      throw new Error(
        "Decryption failed: wrong key, or the share was corrupted.",
      );
    }
    if (meta === null) {
      // Frame 0 carries the encrypted metadata: name, MIME type, size.
      try {
        meta = JSON.parse(decoder.decode(plain));
      } catch {
        throw new Error("Decryption failed: the metadata is unreadable.");
      }
      if (
        typeof meta.name !== "string" ||
        typeof meta.mime !== "string"
      ) {
        throw new Error("Decryption failed: the metadata is invalid.");
      }
      continue;
    }
    if (plain.byteLength === 0) {
      break; // end-of-stream marker
    }
    parts.push(plain);
  }

  if (meta === null) {
    throw new Error("the stream carried no metadata");
  }

  const blob = new Blob(parts, { type: meta.mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = meta.name;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
  return meta;
}

async function init() {
  const id = location.pathname.split("/").pop();
  const keyBytes = keyFromFragment();

  if (!id) {
    showError("No share id in the address.");
    return;
  }
  if (keyBytes === null) {
    showError(
      "This link has no key in it. Ask for the complete link \u2014 the " +
        "part after # is what unlocks the file.",
    );
    return;
  }

  const meta = await fetchMeta(id);
  if (meta.gone) {
    showError(meta.gone);
    return;
  }

  if (meta.one_time) {
    $("warn").hidden = false;
  }
  $("file-line").textContent =
    humanSize(meta.stored_size) +
    " (approximate, encrypted)" +
    " \u00b7 stops working " +
    meta.expires_at +
    " (UTC)";
  $("download-box").hidden = false;

  $("download").addEventListener("click", async (event) => {
    const button = event.target;
    button.disabled = true;
    try {
      const file = await download(id, keyBytes);
      $("state-text").textContent = "Downloaded.";
      $("state-detail").textContent =
        'Saved as "' + file.name + '". If the name looks right, the ' +
        "decryption was clean.";
    } catch (error) {
      showError(
        error instanceof Error && error.message
          ? error.message
          : "something went wrong",
      );
    } finally {
      button.disabled = false;
    }
  });
}

document.addEventListener("DOMContentLoaded", init);
