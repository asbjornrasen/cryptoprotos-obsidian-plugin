"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const obsidian_1 = require("obsidian");
const VERSION = "v1";
function getHeader(iterations, hash) {
    const hashShort = hash === "SHA-512" ? "sha512" : "sha256";
    return `CRYPTOPROTOS${VERSION}i${Math.round(iterations / 1000)}k_${hashShort}:`;
}
const crypto = globalThis.crypto;
const enc = new TextEncoder();
const dec = new TextDecoder();
const DEFAULT_SETTINGS = {
    iterations: 100000,
    hash: "SHA-256"
};
function uint8ArrayToBase64(arr) {
    if (typeof Buffer !== "undefined")
        return Buffer.from(arr).toString("base64");
    let binary = "", CHUNK = 0x8000;
    for (let i = 0; i < arr.length; i += CHUNK) {
        binary += String.fromCharCode.apply(null, arr.subarray(i, i + CHUNK));
    }
    return btoa(binary);
}
function base64ToUint8Array(b64) {
    if (typeof Buffer !== "undefined")
        return Uint8Array.from(Buffer.from(b64, "base64"));
    const binary = atob(b64);
    const arr = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++)
        arr[i] = binary.charCodeAt(i);
    return arr;
}
async function deriveKey(passwordBytes, salt, iterations, hash) {
    const keyMaterial = await crypto.subtle.importKey("raw", passwordBytes, { name: "PBKDF2" }, false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations, hash }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function encryptText(plain, passwordBytes, iterations, hash) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passwordBytes, salt, iterations, hash);
    const encoded = enc.encode(plain);
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
    const combined = new Uint8Array(salt.length + iv.length + cipher.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(cipher), salt.length + iv.length);
    return getHeader(iterations, hash) + uint8ArrayToBase64(combined);
}
async function decryptText(fullText, passwordBytes) {
    const headerMatch = fullText.match(/^CRYPTOPROTOSv1i(\d+)k_(sha256|sha512):/);
    if (!headerMatch)
        throw new Error("no-header");
    const iterations = parseInt(headerMatch[1]) * 1000;
    const hash = headerMatch[2] === "sha256" ? "SHA-256" : "SHA-512";
    const base64Start = headerMatch[0].length;
    const combined = base64ToUint8Array(fullText.slice(base64Start).trim());
    if (combined.length < 28)
        throw new Error("bad-data-length");
    const salt = combined.subarray(0, 16);
    const iv = combined.subarray(16, 28);
    const data = combined.subarray(28);
    const key = await deriveKey(passwordBytes, salt, iterations, hash);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return dec.decode(plain);
}
class PasswordModal extends obsidian_1.Modal {
    constructor(app, promptMsg) {
        super(app);
        this.promptMsg = promptMsg;
    }
    async getPasswordBytes() {
        return new Promise(res => { this.resolve = res; this.open(); });
    }
    onOpen() {
        const { contentEl } = this;
        contentEl.createEl("h3", { text: this.promptMsg });
        const input = contentEl.createEl("input", { type: "password" });
        input.classList.add("cryptoprotos-input");
        input.addEventListener("keydown", e => {
            if (e.key === "Enter") {
                const buf = new Uint8Array(input.value.length);
                for (let i = 0; i < input.value.length; i++)
                    buf[i] = input.value.charCodeAt(i);
                input.value = "";
                this.resolve(buf);
                this.close();
            }
        });
        input.focus();
    }
    onClose() { this.contentEl.empty(); }
}
class ConfirmPasswordModal extends obsidian_1.Modal {
    constructor(app, promptMsg) {
        super(app);
        this.promptMsg = promptMsg;
    }
    async getPasswordBytes() {
        return new Promise(res => { this.resolve = res; this.open(); });
    }
    onOpen() {
        const { contentEl } = this;
        contentEl.createEl("h3", { text: this.promptMsg });
        const input1 = contentEl.createEl("input", { type: "password", placeholder: "Enter password" });
        input1.classList.add("cryptoprotos-input");
        const input2 = contentEl.createEl("input", { type: "password", placeholder: "Confirm password" });
        input2.classList.add("cryptoprotos-input", "cryptoprotos-margin-top");
        const confirmBtn = contentEl.createEl("button", { text: "Confirm" });
        confirmBtn.classList.add("cryptoprotos-margin-top");
        confirmBtn.onclick = () => {
            if (input1.value !== input2.value) {
                new obsidian_1.Notice("❌ Passwords do not match.");
                return;
            }
            const buf = new Uint8Array(input1.value.length);
            for (let i = 0; i < input1.value.length; i++)
                buf[i] = input1.value.charCodeAt(i);
            this.resolve(buf);
            this.close();
        };
        input1.focus();
    }
    onClose() {
        this.contentEl.empty();
    }
}
class CryptoProtosPlugin extends obsidian_1.Plugin {
    constructor() {
        super(...arguments);
        this.settings = DEFAULT_SETTINGS;
    }
    async onload() {
        console.log("✅ CryptoProtos loaded");
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
        const style = document.createElement("style");
        style.id = "cryptoprotos-style";
        style.textContent = `
			.cryptoprotos-input { width: 100%; }
			.cryptoprotos-margin-top { margin-top: 10px; }
		`;
        document.head.appendChild(style);
        this.addCommand({
            id: "encrypt-current-file",
            name: "Encrypt current file with password…",
            checkCallback: checking => {
                const f = this.getActiveFile();
                if (!f)
                    return false;
                if (!checking)
                    this.encryptFile(f);
                return true;
            }
        });
        this.addCommand({
            id: "decrypt-current-file",
            name: "Decrypt current file with password…",
            checkCallback: checking => {
                const f = this.getActiveFile();
                if (!f)
                    return false;
                if (!checking)
                    this.decryptFile(f);
                return true;
            }
        });
        this.addRibbonIcon("lock", "Encrypt active file", async () => {
            const f = this.getActiveFile();
            if (f)
                await this.encryptFile(f);
            else
                new obsidian_1.Notice("No active file");
        });
        this.addRibbonIcon("unlock", "Decrypt active file", async () => {
            const f = this.getActiveFile();
            if (f)
                await this.decryptFile(f);
            else
                new obsidian_1.Notice("No active file");
        });
        const status = this.addStatusBarItem();
        status.setText("CryptoProtos: Enable");
        this.addSettingTab(new CryptoProtosSettingTab(this.app, this));
    }
    onunload() {
        console.log("🧹 CryptoProtos unloaded");
        const style = document.getElementById("cryptoprotos-style");
        if (style)
            style.remove();
    }
    getActiveFile() {
        const f = this.app.workspace.getActiveFile();
        return f && f.extension === "md" ? f : null;
    }
    async promptPassword(confirm = false) {
        if (confirm)
            return new ConfirmPasswordModal(this.app, "Enter and confirm password").getPasswordBytes();
        else
            return new PasswordModal(this.app, "Enter password").getPasswordBytes();
    }
    async encryptFile(file) {
        const passBytes = await this.promptPassword(true);
        if (!passBytes)
            return;
        try {
            const content = await this.app.vault.read(file);
            if (content.startsWith("CRYPTOPROTOS")) {
                new obsidian_1.Notice("⚠ Already encrypted");
                return;
            }
            const encrypted = await encryptText(content, passBytes, this.settings.iterations, this.settings.hash);
            await this.app.vault.modify(file, encrypted);
            new obsidian_1.Notice("🔐 The file is encrypted.");
        }
        catch (err) {
            console.error("[encryptFile] ❌", err);
            new obsidian_1.Notice("❌ Encryption error");
        }
        finally {
            passBytes.fill(0);
        }
    }
    async decryptFile(file) {
        const passBytes = await this.promptPassword();
        if (!passBytes)
            return;
        try {
            const content = await this.app.vault.read(file);
            const decrypted = await decryptText(content, passBytes);
            await this.app.vault.modify(file, decrypted);
            new obsidian_1.Notice("🔓 The file has been decrypted.");
        }
        catch (e) {
            if (e.message === "no-header")
                new obsidian_1.Notice("⚠ Не CryptoProtos‑файл.");
            else
                new obsidian_1.Notice("❌ Incorrect password or corrupted file.");
            console.error("[decryptFile] ❌", e);
        }
        finally {
            passBytes.fill(0);
        }
    }
    async saveSettings() {
        await this.saveData(this.settings);
    }
}
exports.default = CryptoProtosPlugin;
class CryptoProtosSettingTab extends obsidian_1.PluginSettingTab {
    constructor(app, plugin) {
        super(app, plugin);
        this.plugin = plugin;
    }
    display() {
        const { containerEl } = this;
        containerEl.empty();
        containerEl.createEl("h2", { text: "CryptoProtos – Control Panel" });
        new obsidian_1.Setting(containerEl)
            .setName("Iterations (PBKDF2)")
            .setDesc("Choose number of iterations used in key derivation. Note: version 1 used 100,000 by default.")
            .addDropdown(drop => drop.addOption("100000", "100 000 (standard v1.0.0)")
            .addOption("200000", "200 000 (stronger)")
            .addOption("300000", "300 000 (maximum security)")
            .setValue(this.plugin.settings.iterations.toString())
            .onChange(async (value) => {
            this.plugin.settings.iterations = parseInt(value);
            await this.plugin.saveSettings();
        }));
        new obsidian_1.Setting(containerEl)
            .setName("Hash function (PBKDF2)")
            .setDesc("Use SHA-512 for stronger key derivation. Note: version 1 used 256 by default.")
            .addDropdown(drop => drop.addOption("SHA-256", "SHA-256")
            .addOption("SHA-512", "SHA-512")
            .setValue(this.plugin.settings.hash)
            .onChange(async (value) => {
            this.plugin.settings.hash = value;
            await this.plugin.saveSettings();
        }));
        containerEl.createEl("p", { text: "⚠ Make sure you select the same values used when encrypting the file." });
        new obsidian_1.Setting(containerEl)
            .setName("Encrypt the current file")
            .addButton(button => button.setButtonText("Encrypt")
            .onClick(() => {
            const f = this.plugin.getActiveFile();
            if (f)
                this.plugin.encryptFile(f);
        }));
        new obsidian_1.Setting(containerEl)
            .setName("Decrypt the current file")
            .addButton(button => button.setButtonText("Decrypt")
            .onClick(() => {
            const f = this.plugin.getActiveFile();
            if (f)
                this.plugin.decryptFile(f);
        }));
    }
}
