// vault_app.js - Adaptado a la lógica de Python (Hexadecimal)

const te = s => new TextEncoder().encode(s);
const td = b => new TextDecoder().decode(b);

// Funciones para convertir de ArrayBuffer a Hexadecimal (igual que .hex() en Python)
const bufToHex = buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
const hexToBuf = hex => new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

function logEvent(message, type = 'info') {
    const logBox = document.getElementById('audit-log');
    const now = new Date();
    const timeStr = now.toLocaleTimeString();
    const div = document.createElement('div');
    div.className = `log-entry log-${type}`;
    div.innerHTML = `<span class="log-time">[${timeStr}]</span> ${message}`;
    logBox.prepend(div);
}

async function handleEncrypt() {
    const fileInput = document.getElementById('enc-file');
    if (!fileInput.files.length) return alert("Selecciona un archivo");

    const file = fileInput.files[0];
    const data = await file.arrayBuffer();

    try {
        // Generar clave de 256 bits (como tu generate_key en Python)
        const key = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, true, ["encrypt", "decrypt"]);
        const rawKey = await crypto.subtle.exportKey("raw", key);
        const keyHex = bufToHex(rawKey);

        const nonce = crypto.getRandomValues(new Uint8Array(12));
        
        // Metadatos exactos a tu código Python
        const metadata = {
            "filename": file.name,
            "algorithm": "AES-GCM",
            "version": "1.0",
            "timestamp": Math.floor(Date.now() / 1000)
        };
        const aad = te(JSON.stringify(metadata));

        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: nonce, additionalData: aad },
            key,
            data
        );

        const encryptedArr = new Uint8Array(encrypted);
        const ciphertext = encryptedArr.slice(0, -16);
        const tag = encryptedArr.slice(-16);

        // Estructura de contenedor IDÉNTICA a tu Python
        const container = {
            "header": metadata,
            "nonce": bufToHex(nonce),
            "ciphertext": bufToHex(encryptedArr) // WebCrypto incluye el tag al final del ciphertext
        };

        const blob = new Blob([JSON.stringify(container, null, 4)], {type: "application/json"});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = file.name + ".vault.json";
        a.click();

        logEvent(`Archivo cifrado: ${file.name}`, 'success');
        document.getElementById('enc-result').style.display = 'block';
        document.getElementById('enc-result').innerHTML = `<strong>CLAVE HEX (Guárdala):</strong><br><code style="word-break:break-all">${keyHex}</code>`;
    } catch (e) {
        logEvent("Error: " + e.message, 'error');
    }
}

async function handleDecrypt() {
    const fileInput = document.getElementById('dec-file');
    const keyHex = document.getElementById('dec-key').value.trim();
    if (!fileInput.files.length || !keyHex) return alert("Faltan datos");

    try {
        const container = JSON.parse(await fileInput.files[0].text());
        const key = await crypto.subtle.importKey("raw", hexToBuf(keyHex), {name: "AES-GCM"}, true, ["decrypt"]);
        
        const nonce = hexToBuf(container.nonce);
        const ciphertext = hexToBuf(container.ciphertext);
        const aad = te(JSON.stringify(container.header));

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: nonce, additionalData: aad },
            key,
            ciphertext
        );

        const blob = new Blob([decrypted]);
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = container.header.filename;
        a.click();
        logEvent("Archivo descifrado correctamente", 'success');
    } catch (e) {
        logEvent("ERROR: autenticación fallida. El archivo pudo ser manipulado.", 'error');
    }
}