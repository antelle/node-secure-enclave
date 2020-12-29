const assert = require('assert');

const keyTag = 'net.antelle.node-secure-enclave.unit-tests.key';
const keyTagAnother = 'net.antelle.node-secure-enclave.unit-tests.another-key';
const touchIdPrompt = 'something';

describe('node-secure-enclave', function () {
    this.timeout(10000);

    afterEach(async () => {
        await nodeSecureEnclave().deleteKeyPair({ keyTag });
        await nodeSecureEnclave().deleteKeyPair({ keyTag: keyTagAnother });
    });

    it('loads the library', () => {
        assert.ok(nodeSecureEnclave());
    });

    describe('isSupported', () => {
        it('checks if Secure Enclave is supported', () => {
            assert.strictEqual(nodeSecureEnclave().isSupported, true);
        });
    });

    describe('createKeyPair', async () => {
        testCommonMethodBehavior('createKeyPair');

        it('creates a new key pair', async () => {
            const key = await nodeSecureEnclave().createKeyPair({ keyTag });
            assert.ok(key?.publicKey instanceof Buffer);
        });

        it('creates two key pairs', async () => {
            const key = await nodeSecureEnclave().createKeyPair({ keyTag });
            assert.ok(key?.publicKey instanceof Buffer);

            const keyAnother = await nodeSecureEnclave().createKeyPair({ keyTag: keyTagAnother });
            assert.ok(keyAnother?.publicKey instanceof Buffer);

            assert.notStrictEqual(
                keyAnother.publicKey.toString('hex'),
                key.publicKey.toString('hex')
            );
        });

        it('throws an error when key already exists', async () => {
            const key = await nodeSecureEnclave().createKeyPair({ keyTag });
            assert.ok(key?.publicKey instanceof Buffer);

            await assert.rejects(
                async () => {
                    await nodeSecureEnclave().createKeyPair({ keyTag });
                },
                (e) => {
                    return (
                        e.message ===
                            'A key with this keyTag already exists, please delete it first' &&
                        e.keyExists === true
                    );
                }
            );
        });
    });

    describe('deleteKeyPair', () => {
        testCommonMethodBehavior('deleteKeyPair');

        it('deletes a key pair', async () => {
            const key = await nodeSecureEnclave().createKeyPair({ keyTag });
            assert.ok(key?.publicKey instanceof Buffer);

            const deleted = await nodeSecureEnclave().deleteKeyPair({ keyTag });
            assert.strictEqual(deleted, true);

            const newKey = await nodeSecureEnclave().createKeyPair({ keyTag });
            assert.ok(newKey?.publicKey instanceof Buffer);

            assert.notStrictEqual(newKey.publicKey.toString('hex'), key.publicKey.toString('hex'));
        });

        it('throws an error for a non-existing key', async () => {
            const deleted = await nodeSecureEnclave().deleteKeyPair({ keyTag });
            assert.strictEqual(deleted, false);
        });
    });

    describe('findKeyPair', () => {
        testCommonMethodBehavior('findKeyPair');

        it('finds an existing key', async () => {
            const key = await nodeSecureEnclave().createKeyPair({ keyTag });
            assert.ok(key?.publicKey instanceof Buffer);

            const found = await nodeSecureEnclave().findKeyPair({ keyTag });
            assert.ok(found?.publicKey instanceof Buffer);

            assert.strictEqual(found.publicKey.toString('hex'), key.publicKey.toString('hex'));
        });

        it('returns null for a non-existing key', async () => {
            const found = await nodeSecureEnclave().findKeyPair({ keyTag });
            assert.strictEqual(found, null);
        });
    });

    describe('encrypt', () => {
        testDataMethodBehavior('encrypt');
    });

    describe('decrypt', () => {
        testDataMethodBehavior('decrypt');

        it('throws on missing touchIdPrompt', async () => {
            const data = Buffer.from('test');
            await assert.rejects(
                async () => await await nodeSecureEnclave().decrypt({ keyTag, data }),
                /TypeError: touchIdPrompt property is missing/
            );
        });

        it('throws on empty touchIdPrompt', async () => {
            const data = Buffer.from('test');
            await assert.rejects(
                async () => await await nodeSecureEnclave().decrypt({ keyTag, data, touchIdPrompt: '' }),
                /TypeError: touchIdPrompt cannot be empty/
            );
        });

        it('encrypts and decrypts data', async () => {
            const data = Buffer.from('Hello, world!');

            await nodeSecureEnclave().createKeyPair({ keyTag });

            const encrypted = await nodeSecureEnclave().encrypt({ keyTag, data });
            assert.strictEqual(encrypted instanceof Buffer, true);
            assert.notStrictEqual(encrypted.toString('hex'), data.toString('hex'));

            const decrypted = await nodeSecureEnclave().decrypt({ keyTag, touchIdPrompt, data: encrypted });
            assert.strictEqual(decrypted instanceof Buffer, true);
            assert.strictEqual(decrypted.toString('hex'), data.toString('hex'));
        });

        it('throws an error for bad data', async () => {
            const data = Buffer.from('broken');

            await nodeSecureEnclave().createKeyPair({ keyTag });

            await assert.rejects(async () => {
                await nodeSecureEnclave().decrypt({ keyTag, touchIdPrompt, data });
            }, /SecKeyCreateDecryptedData/);
        });
    });

    function nodeSecureEnclave() {
        return require('..');
    }

    function testCommonMethodBehavior(methodName) {
        const method = nodeSecureEnclave()[methodName];

        it(`has ${methodName} method`, () => {
            assert.strictEqual(typeof method, 'function');
        });

        it('throws on empty args', async () => {
            await assert.rejects(
                async () => await method(),
                /TypeError: Expected exactly one argument/
            );
        });

        it('throws on bad arg type', async () => {
            await assert.rejects(
                async () => await method('test'),
                /TypeError: options is not an object/
            );
        });

        it('throws on missing keyTag', async () => {
            await assert.rejects(
                async () => await method({}),
                /TypeError: keyTag property is missing/
            );
        });

        it('throws on bad keyTag type', async () => {
            await assert.rejects(
                async () => await method({ keyTag: 1 }),
                /TypeError: keyTag is not a string/
            );
        });

        it('throws on empty keyTag', async () => {
            await assert.rejects(
                async () => await method({ keyTag: '' }),
                /TypeError: keyTag cannot be empty/
            );
        });
    }

    function testDataMethodBehavior(methodName) {
        testCommonMethodBehavior(methodName);

        const method = nodeSecureEnclave()[methodName];

        it('throws on missing data', async () => {
            await assert.rejects(
                async () => await method({ keyTag, touchIdPrompt }),
                /TypeError: data property is missing/
            );
        });

        it('throws on bad data type', async () => {
            await assert.rejects(
                async () => await method({ keyTag, touchIdPrompt, data: 'test' }),
                /TypeError: data is not a buffer/
            );
        });

        it('throws on empty data', async () => {
            await assert.rejects(
                async () => await method({ keyTag, touchIdPrompt, data: Buffer.alloc(0) }),
                /TypeError: data cannot be empty/
            );
        });

        it('throws on a non-existing key', async () => {
            await assert.rejects(
                async () => await method({ keyTag, touchIdPrompt, data: Buffer.from('data') }),
                (e) => {
                    return (
                        e.message === 'Key not found in Secure Enclave' && e.keyNotFound === true
                    );
                }
            );
        });
    }
});
