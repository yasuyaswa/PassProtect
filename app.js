let mode = "encrypt";

const salt = new TextEncoder().encode("FixedSalt123");

const textEl = document.getElementById("text");
const passEl = document.getElementById("password");
const resultEl = document.getElementById("result");
const outputEl = document.getElementById("output");
const processBtn = document.getElementById("processBtn");
const statusIcon = document.getElementById("statusIcon");
const statusText = document.getElementById("statusText");
const copiedEl = document.getElementById("copied");
const switchEl = document.querySelector(".switch");
const labelEncrypt = document.getElementById("label-encrypt");
const labelDecrypt = document.getElementById("label-decrypt");

[textEl, passEl].forEach(el =>
  el.addEventListener("input", () => resultEl.hidden = true)
);

function toggleMode() {
  mode = mode === "encrypt" ? "decrypt" : "encrypt";
  switchEl.classList.toggle("decrypt");
  labelEncrypt.classList.toggle("active");
  labelDecrypt.classList.toggle("active");
  resultEl.hidden = true;
}

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

async function process() {
  processBtn.disabled = true;
  copiedEl.style.display = "none";
  resultEl.classList.remove("invalid", "shake");

  try {
    const result = mode === "encrypt"
      ? await encrypt(textEl.value, passEl.value)
      : await decrypt(textEl.value, passEl.value);

    statusIcon.textContent = "✔";
    statusText.textContent = "Success";
    outputEl.textContent = result;
  } catch {
    statusIcon.textContent = "⚠";
    statusText.textContent = "Invalid input or password";
    outputEl.textContent = "";
    resultEl.classList.add("invalid", "shake");
  }

  resultEl.hidden = false;
  processBtn.disabled = false;
}

function resetAll() {
  textEl.value = "";
  passEl.value = "";
  resultEl.hidden = true;
}

function copy() {
  navigator.clipboard.writeText(outputEl.textContent);
  copiedEl.style.display = "inline";

  setTimeout(() => copiedEl.style.display = "none", 2000);
}