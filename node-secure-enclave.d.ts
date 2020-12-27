/// <reference types="node" />

declare class EncryptDecryptArg {
    /**
     * Key tag, a unique identifier that tells the Keychain where the key is. Must be globally unique.
     * The tag data is constructed from a string, using reverse DNS notation, though any unique tag will do.
     */
    keyTag: string;

    /**
     * Data you want to decrypt or encrypt.
     */
    data: Buffer;
}

declare class KeyOperationArg {
    /**
     * Key tag, a unique identifier that tells the Keychain where the key is. Must be globally unique.
     * The tag data is constructed from a string, using reverse DNS notation, though any unique tag will do.
     */
    keyTag: string;
}

declare class ResultWithPublicKey {
    /**
     * Serialized public key. Note that the private key is not present here
     * because it's stored on the chip and is never exported from there.
     */
    publicKey: Buffer;
}

declare class NodeSecureEnclave {
    /**
     * Checks if biometric authentication and hardware-based encryption is supported.
     * Should return true on MacBooks with Touch Bar
     */
    static isSupported: boolean;

    /**
     * Creates a new key in the keychain.
     * @param options key creation options
     * @returns created public key
     */
    static createKeyPair(options: KeyOperationArg): ResultWithPublicKey;

    /**
     * Finds an existing key based on key tag.
     * @param options key tag
     * @returns object with publicKey, or null, if the key is not found
     */
    static findKeyPair(options: KeyOperationArg): ResultWithPublicKey | null;

    /**
     * Deletes a key from Keychain and Secure Enclave.
     * @param options key tag
     * @returns true if the key was deleted, false if it's not found, otherwise throws an error
     */
    static deleteKeyPair(options: KeyOperationArg): boolean;

    /**
     * Encrypts the data using the key identified by keyTag.
     * Data doesn't have to be padded, any non-empty Buffer should work
     * @param options
     * @returns encrypted data
     */
    static encrypt(options: EncryptDecryptArg): Buffer;

    /**
     * Decrypts the data using the key identified by keyTag.
     * Data doesn't have to be padded, any non-empty Buffer should work
     * @param options
     * @returns decrypted data
     */
    static decrypt(options: EncryptDecryptArg): Buffer;
}

export = NodeSecureEnclave;
