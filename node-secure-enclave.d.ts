/// <reference types="node" />

declare class KeyOperationArg {
    /**
     * Key tag, a unique identifier that tells the Keychain where the key is. Must be globally unique.
     * The tag data is constructed from a string, using reverse DNS notation, though any unique tag will do.
     * More about this parameter: https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys#2863927
     */
    keyTag: string;
}

declare class EncryptArg extends KeyOperationArg {
    /**
     * Data you want to encrypt, no padding needed.
     */
    data: Buffer;
}

declare class DecryptArg extends KeyOperationArg {
    /**
     * Data you want to decrypt.
     */
    data: Buffer;

    /**
     * Localized text that will be shown during biometric authentication, it will be presented in two forms:
     *  - on the Touch Bar: "Touch ID to {touchIdPrompt}"
     *  - in the modal dialog: "{app} is trying to {touchIdPrompt}"
     *  For example, it can be: "decrypt data", "open file"
     */
    touchIdPrompt: string;
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
     * Creates a new key in the keychain. If a key with this keyTag already exists, an error is thrown.
     * @param options key creation options
     * @returns created public key
     */
    static createKeyPair(options: KeyOperationArg): Promise<ResultWithPublicKey>;

    /**
     * Finds an existing key based on key tag.
     * @param options key tag
     * @returns object with publicKey, or null, if the key is not found
     */
    static findKeyPair(options: KeyOperationArg): Promise<ResultWithPublicKey | null>;

    /**
     * Deletes a key from Keychain and Secure Enclave.
     * @param options key tag
     * @returns true if the key was deleted, false if it's not found, otherwise throws an error
     */
    static deleteKeyPair(options: KeyOperationArg): Promise<boolean>;

    /**
     * Encrypts data on Secure Enclave with a key identified by keyTag
     *  using ECIESEncryptionCofactorVariableIVX963SHA256AESGCM algorithm.
     * Data doesn't have to be padded, any non-empty Buffer should work.
     * Throws an error if the requested key is not found
     *  or there was an encryption error.
     * @param options
     * @returns encrypted data
     */
    static encrypt(options: EncryptArg): Promise<Buffer>;

    /**
     * Decrypts data on Secure Enclave with a key identified by keyTag
     *  using ECIESEncryptionCofactorVariableIVX963SHA256AESGCM algorithm.
     * Accepts data returned by `encrypt`, no padding or encoding is required.
     * This method will show the Touch ID prompt and block until it's approved.
     * Possible cases that can cause an error:
     *  - the requested key is not found => error.keyNotFound = true
     *  - data is invalid or cannot be decrypted with this key => error.badParam = true
     *  - user rejected the Touch ID request using the Cancel button => error.rejected = true
     *  - there was a decryption error
     *  - system refused to show the Touch ID prompt
     *  - Touch ID request timed out
     * @param options
     * @returns decrypted data
     */
    static decrypt(options: DecryptArg): Promise<Buffer>;
}

export = NodeSecureEnclave;
