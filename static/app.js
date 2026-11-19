/* Share creation: pick a file (or a URL), the browser encrypts, the
   ciphertext goes up, the page builds the link with the key in the
   fragment. No frameworks, no CDN, CSP-clean. */

"use strict";

const CHUNK = 4 * 1024 * 1024; // 4 MiB, matches the server's frame limit
const META_LIMIT = 64 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function $(id) {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error("missing element " + id);
  }
  return element;
}

function b64url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function randomKey() {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  return key;
}

async function importKey(raw) {
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
}

async function encryptFrame(key, iv, plaintext) {
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  const frame = new Uint8Array(iv.length + ct.byteLength);
  frame.set(iv, 0);
  frame.set(new Uint8Array(ct), iv.length);
  return frame;
}

function prefixLength(frame) {
  const prefix = new DataView(new ArrayBuffer(4));
  prefix.setUint32(0, frame.length, false);
  return prefix.buffer;
}

function showError(message) {
  const box = $("error");
  box.textContent = message;
  box.hidden = false;
}

function showProgress(label, fraction) {
  $("progress").hidden = false;
  $("progress-bar").style.width = Math.round(fraction * 100) + "%";
  $("progress-label").textContent = label;
}

/* The encrypted stream, in the format the server parses:
   [metadata frame][data frames...] [empty end marker], every frame
   prefixed by its u32 big-endian length. */
async function buildFrames(file, key, onProgress) {
  const cryptoKey = await importKey(key);
  const meta = {
    name: file.name,
    mime: file.type || "application/octet-stream",
    size: file.size,
  };
  const metaPlain = encoder.encode(JSON.stringify(meta));
  if (metaPlain.length > META_LIMIT) {
    throw new Error("the file name is too long to carry");
  }
  const parts = [];
  let iv = crypto.getRandomValues(new Uint8Array(12));
  const metaFrame = await encryptFrame(cryptoKey, iv, metaPlain);
  parts.push(prefixLength(metaFrame), metaFrame);

  for (let offset = 0; offset < file.size; offset += CHUNK) {
    const slice = file.slice(offset, Math.min(offset + CHUNK, file.size));
    const plain = await slice.arrayBuffer();
    iv = crypto.getRandomValues(new Uint8Array(12));
    const frame = await encryptFrame(cryptoKey, iv, plain);
    parts.push(prefixLength(frame), frame);
    onProgress(offset / file.size);
  }

  // Empty end-of-stream marker: a truncated upload cannot look complete.
  iv = crypto.getRandomValues(new Uint8Array(12));
  const marker = await encryptFrame(cryptoKey, iv, new Uint8Array(0));
  parts.push(prefixLength(marker), marker);
  onProgress(1);
  return parts;
}

function finishShare(link, expiresAt) {
  $("progress").hidden = true;
  $("result").hidden = false;
  $("link").value = link;
  $("expiry-note").textContent = "Stops working " + expiresAt + " (UTC).";
  $("copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(link);
      $("copy").textContent = "Copied";
    } catch {
      $("copy").textContent = "Select and copy manually";
    }
  });
}

/* XHR rather than fetch: upload progress events. */
function uploadCiphertext(parts, headers) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/shares");
    for (const [name, value] of Object.entries(headers)) {
      xhr.setRequestHeader(name, value);
    }
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        showProgress("Uploading\u2026", event.loaded / event.total);
      }
    };
    xhr.onload = () => {
      if (xhr.status === 200) {
        resolve(JSON.parse(xhr.responseText));
      } else {
        let detail = "upload failed (" + xhr.status + ")";
        try {
          detail = JSON.parse(xhr.responseText).error || detail;
        } catch {
          /* not JSON, keep the default */
        }
        reject(new Error(detail));
      }
    };
    xhr.onerror = () => reject(new Error("upload failed: network error"));
    xhr.send(new Blob(parts));
  });
}

async function importFromUrl(url, token, ttlDays, oneTime) {
  const response = await fetch("/api/v1/shares/url", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url, ttl_days: ttlDays, one_time: oneTime }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || "import failed (" + response.status + ")");
  }
  finishShare(body.url, body.expires_at);
}

async function onSubmit(event) {
  event.preventDefault();
  $("error").hidden = true;
  $("result").hidden = true;

  const token = $("token").value;
  if (token === "") {
    showError("An admin token is needed to create a share.");
    return;
  }
  const ttlDays = Number($("ttl").value);
  const oneTime = $("one-time").checked;
  const importUrl = $("import-url").value.trim();

  $("send").disabled = true;
  try {
    if (importUrl !== "") {
      showProgress("Fetching and encrypting\u2026", 0.5);
      await importFromUrl(importUrl, token, ttlDays, oneTime);
      return;
    }
    const file = $("file").files[0];
    if (!file) {
      showError("Choose a file, or fill in the URL field.");
      return;
    }
    const key = randomKey();
    showProgress("Encrypting\u2026 0%", 0);
    const parts = await buildFrames(file, key, (fraction) => {
      showProgress("Encrypting\u2026", fraction / 2);
    });
    const created = await uploadCiphertext(parts, {
      Authorization: "Bearer " + token,
      "Content-Type": "application/octet-stream",
      "X-SFS-One-Time": oneTime ? "1" : "0",
      "X-SFS-Ttl-Days": String(ttlDays),
    });
    const link =
      location.origin + "/s/" + created.id + "#key=" + b64url(key);
    finishShare(link, created.expires_at);
  } catch (error) {
    showError(
      error instanceof Error && error.message
        ? error.message
        : "something went wrong",
    );
  } finally {
    $("send").disabled = false;
  }
}

function init() {
  $("share-form").addEventListener("submit", onSubmit);
  const zone = $("drop-zone");
  ["dragenter", "dragover"].forEach((name) => {
    zone.addEventListener(name, (event) => {
      event.preventDefault();
      zone.classList.add("drag");
    });
  });
  ["dragleave", "drop"].forEach((name) => {
    zone.addEventListener(name, (event) => {
      event.preventDefault();
      zone.classList.remove("drag");
    });
  });
  zone.addEventListener("drop", (event) => {
    if (event.dataTransfer && event.dataTransfer.files.length > 0) {
      $("file").files = event.dataTransfer.files;
      updateDropLabel();
    }
  });
  $("file").addEventListener("change", updateDropLabel);
}

function updateDropLabel() {
  const file = $("file").files[0];
  if (file) {
    $("drop-label").textContent = file.name + " (" + humanSize(file.size) + ")";
  } else {
    $("drop-label").textContent =
      "Drop a file here, or click to choose one";
  }
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

document.addEventListener("DOMContentLoaded", init);
