let mode = "encrypt";

const textEl = document.getElementById("text");
const passEl = document.getElementById("password");
const pwdError = document.getElementById("pwdError");
const resultEl = document.getElementById("result");
const outputEl = document.getElementById("output");
const statusIcon = document.getElementById("statusIcon");
const statusText = document.getElementById("statusText");
const copiedEl = document.getElementById("copied");
const copyBtn = document.getElementById("copyBtn");
const downloadBtn = document.getElementById("downloadBtn");
const switchEl = document.getElementById("modeSwitch");
const eyeEl = document.getElementById("eye");

let clearTimer;

/* Encrypt / Decrypt toggle */
function toggleMode() {
  mode = mode === "encrypt" ? "decrypt" : "encrypt";
  switchEl.classList.toggle("encrypt");
  switchEl.classList.toggle("decrypt");
  document.getElementById("label-encrypt").classList.toggle("active");
  document.getElementById("label-decrypt").classList.toggle("active");
  resultEl.hidden = true;
  restartAutoClear();
}

/* Password visibility */
function togglePassword() {
  const show = passEl.type === "password";
  passEl.type = show ? "text" : "password";
  eyeEl.textContent = show ? "🙈" : "👁️";
  restartAutoClear();
}

/* Auto clear after 3 minutes of inactivity */
function startAutoClear() {
  clearTimeout(clearTimer);
  clearTimer = setTimeout(() => {
    resetAll();
    copyBtn.disabled = true;
    downloadBtn.disabled = true;
  }, 180000); // 3 minutes
}

function restartAutoClear() {
  startAutoClear();
}

window.addEventListener("DOMContentLoaded", () => {
  startAutoClear();
  const resetEvents = ["input", "keydown", "mousedown", "mousemove", "touchstart", "focus"];
  resetEvents.forEach(evt => {
    document.addEventListener(evt, restartAutoClear, { passive: true });
  });
});

/* Crypto (AES-GCM + PBKDF2 with fixed salt) */
const salt = new TextEncoder().encode("FixedSalt123"); // For stronger security, prefer per-encryption random salt + store with ciphertext.

async function getKey(password) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(text, password) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await getKey(password);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(text)
  );

  const data = new Uint8Array(iv.length + encrypted.byteLength);
  data.set(iv);
  data.set(new Uint8Array(encrypted), iv.length);

  return btoa(String.fromCharCode(...data));
}

async function decrypt(cipher, password) {
  const data = Uint8Array.from(atob(cipher), c => c.charCodeAt(0));
  const iv = data.slice(0, 12);
  const encrypted = data.slice(12);
  const key = await getKey(password);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    encrypted
  );

  return new TextDecoder().decode(decrypted);
}

/* Status helpers (green success, red/yellow invalid) */
function setSuccess(message = "Success") {
  statusIcon.textContent = "✅";
  statusText.textContent = message;
  resultEl.classList.remove("invalid");
  resultEl.classList.add("success");
}

function setInvalid(type = "error") {
  // type: "error" -> ❌ (red), "warn" -> ⚠️ (yellow)
  statusIcon.textContent = type === "warn" ? "⚠️" : "❌";
  statusText.textContent = type === "warn" ? "Check the input format" : "Invalid input or password";
  resultEl.classList.remove("success");
  resultEl.classList.add("invalid");
}

/* Process */
async function process() {
  pwdError.textContent = "";

  const pwd = passEl.value || "";
  if (pwd.length < 3 || pwd.length > 20) {
    pwdError.textContent = "Password must be 3–20 characters";
    return;
  }

  try {
    const result = mode === "encrypt"
      ? await encrypt(textEl.value, pwd)
      : await decrypt(textEl.value, pwd);

    setSuccess();
    outputEl.textContent = result;

    copyBtn.disabled = false;
    downloadBtn.disabled = false;
    resultEl.hidden = false;
    restartAutoClear();
  } catch (err) {
    const isFormatIssue = typeof err?.message === "string" && /decode|atob|format|malformed/i.test(err.message);
    setInvalid(isFormatIssue ? "warn" : "error");
    resultEl.hidden = false;
  }
}

/* Download */
function downloadTxt() {
  const maskedPwd = "#".repeat(passEl.value.length);
  const content =
`Mode: ${mode.toUpperCase()}
Text:
${textEl.value}

Password:
${maskedPwd}

Output:
${outputEl.textContent}`;

  const blob = new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `secure-${mode}.txt`;
  a.click();
  URL.revokeObjectURL(url);
  restartAutoClear();
}

/* Copy */
function copy() {
  if (!outputEl.textContent) return;
  navigator.clipboard.writeText(outputEl.textContent);
  copiedEl.style.display = "inline";
  setTimeout(() => copiedEl.style.display = "none", 2000);
  restartAutoClear();
}

/* Reset */
function resetAll() {
  textEl.value = "";
  passEl.value = "";
  outputEl.textContent = "";
  resultEl.hidden = true;
  statusIcon.textContent = "";
  statusText.textContent = "";
  copiedEl.style.display = "none";
  copyBtn.disabled = true;
  downloadBtn.disabled = true;
}
