const path = require('path');
const { app, ipcMain, BrowserWindow, nativeTheme } = require('electron');

const secureEnclaveNativeModulePath = path.join(
    __dirname,
    '../bin/darwin-x64-85/node-secure-enclave.node'
);
const keyTag = 'net.antelle.node-secure-enclave.my-key';

ipcMain.handle('cmd', async (e, command, data) => {
    try {
        const secureEnclave = require(secureEnclaveNativeModulePath);
        switch (command) {
            case 'create': {
                const { publicKey } = await secureEnclave.createKeyPair({ keyTag });
                return `Created, public key: ${publicKeyToStr(publicKey)}`;
            }
            case 'find': {
                const result = await secureEnclave.findKeyPair({ keyTag });
                if (!result) {
                    return 'Key not found';
                }
                const { publicKey } = result;
                return `Found, public key: ${publicKeyToStr(publicKey)}`;
            }
            case 'delete': {
                const deleted = await secureEnclave.deleteKeyPair({ keyTag });
                return deleted ? 'Deleted' : 'No key to delete';
            }
            case 'encrypt': {
                if (!data) {
                    return 'Empty data';
                }
                data = Buffer.from(data, 'utf8');
                const encrypted = await secureEnclave.encrypt({ keyTag, data });
                return encrypted.toString('hex');
            }
            case 'decrypt': {
                if (!data) {
                    return 'Empty data';
                }
                data = Buffer.from(data, 'hex');
                const touchIdPrompt = 'decrypt data';
                const decrypted = await secureEnclave.decrypt({ keyTag, data, touchIdPrompt });
                return decrypted.toString('utf8');
            }
            default:
                return 'Not implemented';
        }
    } catch (e) {
        return e.toString();
    }

    function publicKeyToStr(keyData) {
        return keyData.toString('hex').substr(0, 24) + '...';
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

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    app.quit();
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});
