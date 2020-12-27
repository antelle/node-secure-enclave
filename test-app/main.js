const path = require('path');
const { app, ipcMain, BrowserWindow, nativeTheme } = require('electron');

const secureEnclaveNativeModulePath = path.join(
    __dirname,
    '../bin/darwin-x64-85/node-secure-enclave.node'
);
const secureEnclave = require(secureEnclaveNativeModulePath);
const keyTag = 'net.antelle.node-secure-enclave.my-key';

ipcMain.handle('cmd', async (e, command, data) => {
    try {
        switch (command) {
            case 'create': {
                const { publicKey } = secureEnclave.createKeyPair({ keyTag });
                return `Created, public key: ${publicKeyToStr(publicKey)}`;
            }
            case 'find': {
                const result = secureEnclave.findKeyPair({ keyTag });
                if (!result) {
                    return 'Key not found';
                }
                const { publicKey } = result;
                return `Found, public key: ${publicKeyToStr(publicKey)}`;
            }
            case 'delete': {
                const deleted = secureEnclave.deleteKeyPair({ keyTag });
                return deleted ? 'Deleted' : 'No key to delete';
            }
            case 'encrypt': {
                if (!data) {
                    return 'Empty data';
                }
                data = Buffer.from(data, 'utf8');
                const encrypted = secureEnclave.encrypt({ keyTag, data });
                return encrypted.toString('hex');
            }
            case 'decrypt': {
                if (!data) {
                    return 'Empty data';
                }
                data = Buffer.from(data, 'hex');
                const decrypted = secureEnclave.decrypt({ keyTag, data });
                return decrypted.toString('utf8');
            }
            default:
                return 'Not implemented';
        }
    } catch (e) {
        return e.toString();
    }
});

function createWindow() {
    const win = new BrowserWindow({
        width: 600,
        height: 480,
        minWidth: 500,
        minHeight: 380,
        backgroundColor: nativeTheme.shouldUseDarkColors ? '#1E1E1E' : '#FFFFFF',
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: path.join(__dirname, 'preload.js')
        }
    });

    win.loadFile('index.html');
}

function publicKeyToStr(keyData) {
    return keyData.toString('hex').substr(0, 24) + '...';
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    app.quit();
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});
