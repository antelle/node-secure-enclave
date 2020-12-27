/// <reference types="node" />

declare class EncryptDecryptArg {
    keyTag: string;
    data: Buffer;
}

declare class KeyOperationArg {
    keyTag: string;
}

declare class ResultWithPublicKey {
    publicKey: Buffer;
}

declare class NodeSecureEnclave {
    static isSupported: boolean;

    static createKeyPair(options: KeyOperationArg): ResultWithPublicKey;
    static findKeyPair(options: KeyOperationArg): ResultWithPublicKey;
    static deleteKeyPair(options: KeyOperationArg): boolean;

    static encrypt(options: EncryptDecryptArg): Buffer;
    static decrypt(options: EncryptDecryptArg): Buffer;
}

export = NodeSecureEnclave;
