const assert = require('assert');

const keyTag = 'net.antelle.node-secure-enclave.unit-tests.key';
const keyTagAnother = 'net.antelle.node-secure-enclave.unit-tests.another-key';

describe('node-secure-enclave', function () {
    this.timeout(10000);

    afterEach(() => {
        nodeSecureEnclave().deleteKeyPair({ keyTag });
        nodeSecureEnclave().deleteKeyPair({ keyTag: keyTagAnother });
    });

    it('loads the library', () => {
        assert.ok(nodeSecureEnclave());
    });

    describe('isSupported', () => {
        it('checks if Secure Enclave is supported', () => {
            assert.strictEqual(nodeSecureEnclave().isSupported, true);
        });
    });

    describe('createKeyPair', () => {
        testCommonMethodBehavior('createKeyPair');

        it('creates a new key pair', () => {
            const key = nodeSecureEnclave().createKeyPair({ keyTag });
            assert.ok(key?.publicKey instanceof Buffer);
        });

        it('creates two key pairs', () => {
            const key = nodeSecureEnclave().createKeyPair({ keyTag });
            assert.ok(key?.publicKey instanceof Buffer);

            const keyAnother = nodeSecureEnclave().createKeyPair({ keyTag: keyTagAnother });
            assert.ok(keyAnother?.publicKey instanceof Buffer);

            assert.notStrictEqual(
                keyAnother.publicKey.toString('hex'),
                key.publicKey.toString('hex')
            );
        });

        it('throws an error when key already exists', () => {
            const key = nodeSecureEnclave().createKeyPair({ keyTag });
            assert.ok(key?.publicKey instanceof Buffer);

            assert.throws(
                () => nodeSecureEnclave().createKeyPair({ keyTag }),
                (e) => {
                    return (
                        e.message ===
                            'A key with this keyTag already exists, please delete it first' &&
                        e.exists === true
                    );
                }
            );
        });
    });

    describe('deleteKeyPair', () => {
        testCommonMethodBehavior('deleteKeyPair');

        it('deletes a key pair', () => {
            const key = nodeSecureEnclave().createKeyPair({ keyTag });
            assert.ok(key?.publicKey instanceof Buffer);

            const deleted = nodeSecureEnclave().deleteKeyPair({ keyTag });
            assert.strictEqual(deleted, true);

            const newKey = nodeSecureEnclave().createKeyPair({ keyTag });
            assert.ok(newKey?.publicKey instanceof Buffer);

            assert.notStrictEqual(newKey.publicKey.toString('hex'), key.publicKey.toString('hex'));
        });

        it('throws an error for a non-existing key', () => {
            const deleted = nodeSecureEnclave().deleteKeyPair({ keyTag });
            assert.strictEqual(deleted, false);
        });
    });

    describe('findKeyPair', () => {
        testCommonMethodBehavior('findKeyPair');

        it('finds an existing key', () => {
            const key = nodeSecureEnclave().createKeyPair({ keyTag });
            assert.ok(key?.publicKey instanceof Buffer);

            const found = nodeSecureEnclave().findKeyPair({ keyTag });
            assert.ok(found?.publicKey instanceof Buffer);

            assert.strictEqual(found.publicKey.toString('hex'), key.publicKey.toString('hex'));
        });

        it('returns null for a non-existing key', () => {
            const found = nodeSecureEnclave().findKeyPair({ keyTag });
            assert.strictEqual(found, null);
        });
    });

    describe('encrypt and decrypt', () => {
        testDataMethodBehavior('encrypt');
        testDataMethodBehavior('decrypt');

        it('encrypts and decrypts data', () => {
            const data = Buffer.from('Hello, world!');

            nodeSecureEnclave().createKeyPair({ keyTag });

            const encrypted = nodeSecureEnclave().encrypt({ keyTag, data });
            assert.strictEqual(encrypted instanceof Buffer, true);
            assert.notStrictEqual(encrypted.toString('hex'), data.toString('hex'));

            const decrypted = nodeSecureEnclave().decrypt({ keyTag, data: encrypted });
            assert.strictEqual(decrypted instanceof Buffer, true);
            assert.strictEqual(decrypted.toString('hex'), data.toString('hex'));
        });

        it('throws an error for bad data', () => {
            const data = Buffer.from('broken');

            nodeSecureEnclave().createKeyPair({ keyTag });

            assert.throws(
                () => nodeSecureEnclave().decrypt({ keyTag, data }),
                /SecKeyCreateDecryptedData/
            );
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

        it('throws on empty args', () => {
            assert.throws(() => method(), /TypeError: Expected exactly one argument/);
        });

        it('throws on bad arg type', () => {
            assert.throws(() => method('test'), /TypeError: options is not an object/);
        });

        it('throws on missing keyTag', () => {
            assert.throws(() => method({}), /TypeError: keyTag property is missing/);
        });

        it('throws on bad keyTag type', () => {
            assert.throws(() => method({ keyTag: 1 }), /TypeError: keyTag is not a string/);
        });

        it('throws on empty keyTag', () => {
            assert.throws(() => method({ keyTag: '' }), /TypeError: keyTag cannot be empty/);
        });
    }

    function testDataMethodBehavior(methodName) {
        testCommonMethodBehavior(methodName);

        const method = nodeSecureEnclave()[methodName];

        it('throws on missing data', () => {
            assert.throws(() => method({ keyTag }), /TypeError: data property is missing/);
        });

        it('throws on bad data type', () => {
            assert.throws(
                () => method({ keyTag, data: 'test' }),
                /TypeError: data is not a buffer/
            );
        });

        it('throws on empty data', () => {
            assert.throws(
                () => method({ keyTag, data: Buffer.alloc(0) }),
                /TypeError: data cannot be empty/
            );
        });

        it('throws on a non-existing key', () => {
            assert.throws(
                () => method({ keyTag, data: Buffer.from('data') }),
                (e) => {
                    return (
                        e.message === 'Key not found in Secure Enclave' && e.keyNotFound === true
                    );
                }
            );
        });
    }
});
