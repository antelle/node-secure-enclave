window.addEventListener('DOMContentLoaded', () => {
    const inputArea = document.querySelector('#input-area');
    const inputEl = document.querySelector('#input-data');
    const resultEl = document.querySelector('#result');
    let inputCommand;
    let lastEncryptedData;

    document.addEventListener('click', async (e) => {
        const btn = e.target.closest('button[data-command]');
        if (!btn) {
            return;
        }
        const { command } = btn.dataset;
        const needsData = command === 'encrypt' || command === 'decrypt';
        if (needsData) {
            const visible = !inputArea.classList.toggle('hide');
            if (visible) {
                inputCommand = command;
                if (command === 'decrypt' && lastEncryptedData) {
                    inputEl.value = lastEncryptedData;
                    lastEncryptedData = undefined;
                    inputEl.select();
                } else {
                    inputEl.value = '';
                }
                inputEl.focus();
            }
            return;
        }
        await runCommand(command);
    });

    async function runCommand(command, data) {
        const { ipcRenderer } = require('electron');
        document.querySelector('#result').innerText = '';
        let result;
        try {
            result = await ipcRenderer.invoke('cmd', command, data);
            if (command === 'encrypt') {
                lastEncryptedData = result;
            }
        } catch (e) {
            result = e.toString();
        }
        resultEl.innerText = result;
        resultEl.classList.toggle('error', /^\w*Error:/.test(result));
    }

    document.addEventListener('click', (e) => {
        const link = e.target.closest('a');
        if (link) {
            const { shell } = require('electron');
            e.preventDefault();
            shell.openExternal(link.href);
        }
    });

    inputEl.addEventListener('keyup', async (e) => {
        if (e.key === 'Enter') {
            inputArea.classList.add('hide');
            await runCommand(inputCommand, inputEl.value);
        } else if (e.key === 'Escape') {
            inputArea.classList.add('hide');
        }
    });
});
