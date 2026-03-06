// vault_app.js
// Lógica criptográfica y de interfaz para Secure Digital Document Vault

const ALGO = "AES-GCM-256-v1";
const te = s => new TextEncoder().encode(s);
const b64e = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

// --- SISTEMA DE LOGS DE AUDITORÍA ---
function logEvent(message, type = 'info') {
  const logBox = document.getElementById('audit-log');
  if (!logBox) return; // Por si el contenedor no existe aún
  
  const now = new Date();
  const timeStr = now.toLocaleTimeString() + '.' + now.getMilliseconds().toString().padStart(3, '0');
  
  const div = document.createElement('div');
  div.className = `log-entry log-${type}`;
  div.innerHTML = `<span class="log-time">[${timeStr}]</span> ${message}`;
  
  // Agrega al principio (arriba)
  logBox.prepend(div);
}

// --- HELPER PARA DESCARGAR ARCHIVOS ---
function downloadFile(content, fileName, isJson = false) {
  const blob = isJson ? new Blob([content], { type: 'application/json' }) : new Blob([content]);
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  logEvent(`Descarga iniciada para el archivo: ${fileName}`, 'info');
}

// --- LÓGICA DE ENCRIPTACIÓN ---
async function handleEncrypt() {
  const fileInput = document.getElementById('enc-file');
  const resBox = document.getElementById('enc-result');
  
  if (!fileInput.files.length) {
    logEvent('Intento de cifrado fallido: No se seleccionó archivo.', 'error');
    resBox.className = 'result-box error';
    resBox.innerHTML = '⚠️ Por favor selecciona un archivo.';
    return;
  }
  
  const file = fileInput.files[0];
  const arrayBuffer = await file.arrayBuffer();
  logEvent(`Iniciando cifrado AES-GCM para: ${file.name} (${file.size} bytes)`, 'info');
  
  try {
    // 1. Generación de clave
    const key = await crypto.subtle.generateKey({name:"AES-GCM", length:256}, true, ["encrypt","decrypt"]);
    const keyB64 = b64e(await crypto.subtle.exportKey("raw", key));
    logEvent('Clave criptográfica de 256 bits generada (Aleatoriedad OS-Level).', 'success');

    // 2. Generación de Nonce
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    logEvent('Nonce criptográfico de 96 bits generado.', 'success');
    
    // 3. Metadatos (AAD)
    const metadata = { 
        filename: file.name, 
        algorithm: ALGO, 
        key_size_bits: 256, 
        nonce_size_bits: 96, 
        created_at: new Date().toISOString() 
    };
    const aadBytes = te(JSON.stringify(metadata));
    
    // 4. Cifrado
    const ctWithTag = await crypto.subtle.encrypt(
        {name:"AES-GCM", iv: nonce, additionalData: aadBytes, tagLength: 128}, 
        key, 
        arrayBuffer
    );
    const ctArr = new Uint8Array(ctWithTag);
    logEvent(`Cifrado completado. Auth Tag (128 bits) adherida.`, 'success');
    
    // 5. Construcción del contenedor
    const container = {
      header: { metadata, aad_b64: b64e(aadBytes) },
      nonce_b64: b64e(nonce),
      ciphertext_b64: b64e(ctArr.slice(0, -16)),
      auth_tag_b64: b64e(ctArr.slice(-16))
    };
    
    // 6. Descarga y actualización de UI
    const jsonString = JSON.stringify(container, null, 2);
    downloadFile(jsonString, `${file.name}.vault.json`, true);
    logEvent('Contenedor Vault construido y exportado exitosamente.', 'success');
    
    resBox.className = 'result-box success';
    resBox.innerHTML = `✅ Archivo cifrado con éxito.\nSe ha descargado el contenedor (.json).\n\n<span class="key-highlight">🔑 GUARDA ESTA CLAVE: <br>${keyB64}</span>\nSi la pierdes, el archivo será irrecuperable.`;
    
  } catch(e) {
    logEvent(`Error crítico durante el cifrado: ${e.message}`, 'error');
    resBox.className = 'result-box error';
    resBox.innerHTML = `❌ Error al cifrar: ${e.message}`;
  }
}

// --- LÓGICA DE DESENCRIPTACIÓN ---
async function handleDecrypt() {
  const fileInput = document.getElementById('dec-file');
  const keyStr = document.getElementById('dec-key').value.trim();
  const resBox = document.getElementById('dec-result');
  
  if (!fileInput.files.length || !keyStr) {
    logEvent('Intento de descifrado fallido: Faltan datos (archivo o clave).', 'error');
    resBox.className = 'result-box error';
    resBox.innerHTML = '⚠️ Selecciona el archivo JSON e ingresa la clave.';
    return;
  }
  
  const file = fileInput.files[0];
  const fileText = await file.text();
  logEvent(`Iniciando lectura de contenedor: ${file.name}`, 'info');
  
  try {
    // 1. Parseo del JSON
    const container = JSON.parse(fileText);
    logEvent('Estructura JSON parseada correctamente. Extrayendo Metadatos (AAD).', 'info');

    // 2. Importar Clave
    const key = await crypto.subtle.importKey("raw", b64d(keyStr), {name:"AES-GCM"}, true, ["encrypt","decrypt"]);
    
    // 3. Reensamblar Ciphertext y Auth Tag
    const ct = b64d(container.ciphertext_b64);
    const tag = b64d(container.auth_tag_b64);
    const ctWithTag = new Uint8Array(ct.length + tag.length);
    ctWithTag.set(ct); 
    ctWithTag.set(tag, ct.length);
    
    logEvent('Iniciando proceso de autenticación de etiqueta (Tamper Check)...', 'warning');
    
    // 4. Descifrado y Verificación de Integridad
    const ptBuffer = await crypto.subtle.decrypt(
      {name:"AES-GCM", iv: b64d(container.nonce_b64), additionalData: b64d(container.header.aad_b64), tagLength: 128},
      key, 
      ctWithTag
    );
    
    logEvent('¡Autenticación exitosa! Integridad comprobada.', 'success');
    
    // 5. Recuperar nombre original y descargar
    const originalName = container.header.metadata.filename || 'documento_descifrado.bin';
    downloadFile(ptBuffer, originalName);
    logEvent(`Archivo original recuperado: ${originalName}`, 'success');
    
    resBox.className = 'result-box success';
    resBox.innerHTML = `✅ DESCIFRADO EXITOSO:\nSe ha descargado tu archivo original (${originalName}).`;
    
  } catch (e) {
    logEvent('🚨 ALERTA DE SEGURIDAD: Fallo de autenticación. Posible manipulación de datos (Tamper) o clave incorrecta.', 'error');
    resBox.className = 'result-box error';
    resBox.innerHTML = `❌ FALLO DE AUTENTICACIÓN:\nDatos manipulados, contenedor corrupto o clave incorrecta.`;
  }
}