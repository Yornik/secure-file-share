/* Share creation: pick a file (or a URL), the browser encrypts with a
   hybrid post-quantum key (ML-KEM-1024 encapsulation + AES-256-GCM), the
   ciphertext goes up, the page builds the link with the unlock material
   in the fragment. No frameworks, no CDN, CSP-clean.

   The unlock material never leaves this page except inside the link's
   #fragment, which browsers do not send to any server. */

"use strict";

const CHUNK = 4 * 1024 * 1024; // 4 MiB, matches the server's frame limit
const META_LIMIT = 64 * 1024;
const KEM_CT_LEN = 1568; // ML-KEM-1024 ciphertext, FIPS 203 Table 3
const SK_SEED_LEN = 64; // ML-KEM-1024 keygen seed (d || z)
const RND_LEN = 32; // the hybrid's random value
const HKDF_SALT = "secure-file-share/v2";
const HKDF_INFO = "file key";
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

/* The hybrid file key: HKDF-SHA256 over the encapsulated secret and the
   random value. Both must break for the key to fall. */
function deriveFileKey(sharedSecret, rnd) {
  const ikm = new Uint8Array(sharedSecret.length + rnd.length);
  ikm.set(sharedSecret, 0);
  ikm.set(rnd, sharedSecret.length);
  return new Uint8Array(
    SFS_PQ.hkdf(
      SFS_PQ.sha256,
      ikm,
      encoder.encode(HKDF_SALT),
      encoder.encode(HKDF_INFO),
      32,
    ),
  );
}

async function importAesKey(raw) {
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
   [KEM ciphertext frame][metadata frame][data frames...] [empty marker],
   every frame prefixed by its u32 big-endian length. The ML-KEM seed and
   the random value travel only in the returned unlock material. */
async function buildFrames(file, onProgress) {
  // The seeds: 64 bytes regenerate the same ML-KEM keypair everywhere
  // (deterministic keygen, FIPS 203), 32 bytes carry the hybrid's random
  // half. Together they are the unlock material for the link.
  const skSeed = new Uint8Array(SK_SEED_LEN);
  crypto.getRandomValues(skSeed);
  const rnd = new Uint8Array(RND_LEN);
  crypto.getRandomValues(rnd);

  const { publicKey } = SFS_PQ.ml_kem1024.keygen(skSeed);
  const { cipherText, sharedSecret } = SFS_PQ.ml_kem1024.encapsulate(publicKey);
  if (cipherText.length !== KEM_CT_LEN) {
    throw new Error("unexpected ML-KEM-1024 ciphertext size");
  }
  const fileKey = await importAesKey(deriveFileKey(sharedSecret, rnd));

  const meta = {
    // 120 code points, the same cap the server applies to URL imports;
    // the name is a display label, and both paths must agree.
    name: [...file.name].slice(0, 120).join(""),
    mime: file.type || "application/octet-stream",
    size: file.size,
  };
  const metaPlain = encoder.encode(JSON.stringify(meta));
  if (metaPlain.length > META_LIMIT) {
    throw new Error("the file name is too long to carry");
  }

  const parts = [];
  parts.push(prefixLength(cipherText), cipherText);
  let iv = crypto.getRandomValues(new Uint8Array(12));
  const metaFrame = await encryptFrame(fileKey, iv, metaPlain);
  parts.push(prefixLength(metaFrame), metaFrame);

  for (let offset = 0; offset < file.size; offset += CHUNK) {
    const slice = file.slice(offset, Math.min(offset + CHUNK, file.size));
    const plain = await slice.arrayBuffer();
    iv = crypto.getRandomValues(new Uint8Array(12));
    const frame = await encryptFrame(fileKey, iv, plain);
    parts.push(prefixLength(frame), frame);
    onProgress(offset / file.size);
  }

  // Empty end-of-stream marker: a truncated upload cannot look complete.
  iv = crypto.getRandomValues(new Uint8Array(12));
  const marker = await encryptFrame(fileKey, iv, new Uint8Array(0));
  parts.push(prefixLength(marker), marker);
  onProgress(1);

  const unlock = new Uint8Array(SK_SEED_LEN + RND_LEN);
  unlock.set(skSeed, 0);
  unlock.set(rnd, SK_SEED_LEN);
  return { parts, unlock };
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
    showProgress("Encrypting\u2026 0%", 0);
    const { parts, unlock } = await buildFrames(file, (fraction) => {
      showProgress("Encrypting\u2026", fraction / 2);
    });
    const created = await uploadCiphertext(parts, {
      Authorization: "Bearer " + token,
      "Content-Type": "application/octet-stream",
      "X-SFS-One-Time": oneTime ? "1" : "0",
      "X-SFS-Ttl-Days": String(ttlDays),
    });
    const link =
      location.origin + "/s/" + created.id + "#key=" + b64url(unlock);
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
