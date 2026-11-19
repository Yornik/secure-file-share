/* Operator control plane: look up and delete a share by its link. The
   control token is typed into the page and travels as a bearer header
   on each request; nothing is stored anywhere. No frameworks, no CDN,
   CSP-clean. */

"use strict";

let deleteArmed = false;

function $(id) {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error("missing element " + id);
  }
  return element;
}

async function callControlPlane(path, token, link) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ link: link }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || "the control plane answered " + response.status);
  }
  return body;
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

function line(label, value) {
  const paragraph = document.createElement("p");
  const name = document.createElement("span");
  name.className = "field-label";
  name.textContent = label + " ";
  paragraph.appendChild(name);
  paragraph.append(value);
  return paragraph;
}

function showRecord(record, note) {
  const box = $("result");
  box.replaceChildren(
    line("Share id", record.id),
    line("Stored size", humanSize(record.stored_size) + " (" + record.stored_size + " bytes)"),
    line("Burn after reading", record.one_time ? "yes" : "no"),
    line("Downloads", String(record.downloads)),
    line("Created", record.created_at),
    line("Expires", record.expires_at),
  );
  const hint = document.createElement("p");
  hint.className = "hint";
  hint.textContent = note;
  box.append(hint);
  box.hidden = false;
}

function showError(message) {
  const box = $("error");
  box.textContent = message;
  box.hidden = false;
}

/* The delete needs a second, deliberate click. Any edit to the form
   disarms it again: the confirm must always follow the exact link the
   operator is looking at right now. */
function disarmDelete() {
  deleteArmed = false;
  $("delete").textContent = "Delete";
  $("confirm").hidden = true;
}

function readLink() {
  const link = $("link").value.trim();
  if (link === "") {
    showError("Paste a share link first.");
    return null;
  }
  return link;
}

async function onLookup(event) {
  event.preventDefault();
  disarmDelete();
  $("error").hidden = true;
  $("result").hidden = true;
  const link = readLink();
  if (link === null) {
    return;
  }
  $("lookup").disabled = true;
  try {
    const record = await callControlPlane("/lookup", $("token").value, link);
    showRecord(record, "The bookkeeping row, exactly as the server keeps it.");
  } catch (error) {
    showError(error instanceof Error && error.message ? error.message : "lookup failed");
  } finally {
    $("lookup").disabled = false;
  }
}

async function onDelete() {
  $("error").hidden = true;
  $("result").hidden = true;
  const link = readLink();
  if (link === null) {
    disarmDelete();
    return;
  }
  if (!deleteArmed) {
    deleteArmed = true;
    $("delete").textContent = "Confirm delete";
    $("confirm").hidden = false;
    return;
  }
  disarmDelete();
  $("delete").disabled = true;
  try {
    const record = await callControlPlane("/delete", $("token").value, link);
    showRecord(record, "Deleted. The row and the file are gone.");
  } catch (error) {
    showError(error instanceof Error && error.message ? error.message : "delete failed");
  } finally {
    $("delete").disabled = false;
  }
}

function init() {
  $("control-form").addEventListener("submit", onLookup);
  $("delete").addEventListener("click", onDelete);
  $("link").addEventListener("input", disarmDelete);
  $("token").addEventListener("input", disarmDelete);
}

document.addEventListener("DOMContentLoaded", init);
