const salt = new TextEncoder().encode("SecureVaultSalt");

function passwordStrength(pwd) {
  if (pwd.length < 6) return "Weak";
  if (pwd.match(/[A-Z]/) && pwd.match(/[0-9]/)) return "Strong";
  return "Medium";
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
  const mode = document.getElementById("mode").value;
  const text = document.getElementById("text").value;
  const password = document.getElementById("password").value;

  document.getElementById("strength").textContent =
    "Password strength: " + passwordStrength(password);

  try {
    const output = mode === "encrypt"
      ? await encrypt(text, password)
      : await decrypt(text, password);

    document.getElementById("output").textContent = output;
    document.getElementById("result").hidden = false;
  } catch {
    alert("Invalid password or input");
  }
}

function clearAll() {
  text.value = password.value = "";
  result.hidden = true;
}

function copy() {
  navigator.clipboard.writeText(output.textContent);
}
