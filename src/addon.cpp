#include "auto_release.h"
#include "helpers.h"
#include <napi.h>
#include <Security/Security.h>

static const int KEY_SIZE_IN_BITS = 256;

Napi::Value isSupported(const Napi::CallbackInfo& info) {
    return Napi::Boolean::New(info.Env(), isBiometricAuthSupported());
}

Napi::Value createKeyPair(const Napi::CallbackInfo& info) {
    auto env = info.Env();

    if (!isBiometricAuthSupported()) {
        return throwNotSupportedError(env);
    }
    
    auto_release queryAttributes = getKeyQueryAttributesFromArgs(info);
    if (!queryAttributes) {
        return env.Null();
    }

    auto_release<SecKeyRef> existingPrivateKey = nullptr;
    auto existingKeyStatus = SecItemCopyMatching(queryAttributes, (CFTypeRef*)(&existingPrivateKey));

    if (existingKeyStatus == errSecSuccess) {
        auto err = Napi::Error::New(env, "A key with this keyTag already exists, please delete it first");
        err.Set("exists", Napi::Boolean::New(env, true));
        err.ThrowAsJavaScriptException();
        return env.Null();
    } else if (existingKeyStatus != errSecItemNotFound) {
        return throwErrorWithCode(env, existingKeyStatus, "SecItemCopyMatching");
    }

    auto_release keyTagData = getKeyTagFromArgs(info);
    if (!keyTagData) {
        return env.Null();
    }

    auto_release keySize = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &KEY_SIZE_IN_BITS);

    auto_release access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
        nullptr);

    auto_release creteKeyAttributes = CFDictionaryCreateMutable(kCFAllocatorDefault,
        0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    auto_release privateKeyAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault,
        0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionaryAddValue(privateKeyAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionaryAddValue(privateKeyAttrs, kSecAttrApplicationTag, keyTagData);
    CFDictionaryAddValue(privateKeyAttrs, kSecAttrAccessControl, access);

    CFDictionaryAddValue(creteKeyAttributes, kSecAttrKeyType, kSecAttrKeyTypeEC);
    CFDictionaryAddValue(creteKeyAttributes, kSecAttrKeySizeInBits, keySize);
    CFDictionaryAddValue(creteKeyAttributes, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionaryAddValue(creteKeyAttributes, kSecPrivateKeyAttrs, privateKeyAttrs);

    CFErrorRef error = nullptr;
    auto_release privateKey = SecKeyCreateRandomKey(creteKeyAttributes, &error);
    if (!privateKey) {
        return throwErrorWithCFError(env, error, "SecKeyCreateRandomKey");
    }

    auto_release publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) {
        Napi::Error::New(env, "Can't extract public key").ThrowAsJavaScriptException();
        return env.Null();
    }

    auto_release publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error);
    if (!publicKeyData) {
        return throwErrorWithCFError(env, error, "SecKeyCopyExternalRepresentation");
    }

    auto ret = Napi::Object::New(env);
    ret.Set("publicKey", cfDataToBuffer(env, publicKeyData));
    return ret;
}

Napi::Value findKeyPair(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!isBiometricAuthSupported()) {
        return throwNotSupportedError(env);
    }

    auto_release queryAttributes = getKeyQueryAttributesFromArgs(info);
    if (!queryAttributes) {
        return env.Null();
    }

    auto_release<SecKeyRef> privateKey = nullptr;
    auto status = SecItemCopyMatching(queryAttributes, (CFTypeRef*)(&privateKey));

    if (status == errSecItemNotFound) {
        return env.Null();
    } else if (status != errSecSuccess) {
        return throwErrorWithCode(env, status, "SecItemCopyMatching");
    }

    auto_release publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) {
        Napi::Error::New(env, "Can't extract public key").ThrowAsJavaScriptException();
        return env.Null();
    }

    CFErrorRef error = nullptr;
    auto_release publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error);
    if (!publicKeyData) {
        return throwErrorWithCFError(env, error, "SecKeyCopyExternalRepresentation");
    }

    auto ret = Napi::Object::New(env);
    ret.Set("publicKey", cfDataToBuffer(env, publicKeyData));
    return ret;
}

Napi::Value deleteKeyPair(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!isBiometricAuthSupported()) {
        return throwNotSupportedError(env);
    }

    auto_release queryAttributes = getKeyQueryAttributesFromArgs(info);
    if (!queryAttributes) {
        return env.Null();
    }

    auto status = SecItemDelete(queryAttributes);

    if (status == errSecItemNotFound) {
        return Napi::Boolean::New(env, false);
    } else if (status != errSecSuccess) {
        return throwErrorWithCode(env, status, "SecItemDelete");
    }

    return Napi::Boolean::New(env, true);
}

Napi::Value encryptData(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!isBiometricAuthSupported()) {
        return throwNotSupportedError(env);
    }

    auto_release queryAttributes = getKeyQueryAttributesFromArgs(info);
    if (!queryAttributes) {
        return env.Null();
    }

    auto_release<SecKeyRef> privateKey = nullptr;
    auto status = SecItemCopyMatching(queryAttributes, (CFTypeRef*)(&privateKey));

    if (status != errSecSuccess) {
        return throwErrorWithCode(env, status, "SecItemCopyMatching");
    }

    auto_release publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) {
        Napi::Error::New(env, "Can't extract public key").ThrowAsJavaScriptException();
        return env.Null();
    }

    auto_release decryptedData = getDataFromArgs(info);
    if (!decryptedData) {
        return env.Null();
    }

    auto supported = SecKeyIsAlgorithmSupported(publicKey, kSecKeyOperationTypeEncrypt,
        kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM);
    if (!supported) {
        Napi::Error::New(env, "Algorithm not supported").ThrowAsJavaScriptException();
        return env.Null();
    }

    CFErrorRef error = nullptr;
    auto_release encryptedData = SecKeyCreateEncryptedData(publicKey,
        kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
        decryptedData, &error);
    if (error) {
        return throwErrorWithCFError(env, error, "SecKeyCreateEncryptedData");
    }

    return cfDataToBuffer(env, encryptedData);
}

Napi::Value decryptData(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!isBiometricAuthSupported()) {
        return throwNotSupportedError(env);
    }

    auto_release queryAttributes = getKeyQueryAttributesFromArgs(info);
    if (!queryAttributes) {
        return env.Null();
    }

    auto_release<SecKeyRef> privateKey = nullptr;
    auto status = SecItemCopyMatching(queryAttributes, (CFTypeRef*)(&privateKey));

    if (status != errSecSuccess) {
        return throwErrorWithCode(env, status, "SecItemCopyMatching");
    }

    auto_release encryptedData = getDataFromArgs(info);
    if (!encryptedData) {
        return env.Null();
    }

    auto supported = SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeDecrypt,
        kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM);
    if (!supported) {
        Napi::Error::New(env, "Algorithm not supported").ThrowAsJavaScriptException();
        return env.Null();
    }

    CFErrorRef error = nullptr;
    auto_release decryptedData = SecKeyCreateDecryptedData(privateKey,
        kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
        encryptedData, &error);
    if (error) {
        return throwErrorWithCFError(env, error, "SecKeyCreateDecryptedData");
    }

    return cfDataToBuffer(env, decryptedData);
}

Napi::Object init(Napi::Env env, Napi::Object exports) {
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor<isSupported>("isSupported", napi_enumerable));
    exports.Set("isSupported", Napi::Function::New(env, isSupported));

    exports.Set("createKeyPair", Napi::Function::New(env, createKeyPair));
    exports.Set("findKeyPair", Napi::Function::New(env, findKeyPair));
    exports.Set("deleteKeyPair", Napi::Function::New(env, deleteKeyPair));

    exports.Set("encrypt", Napi::Function::New(env, encryptData));
    exports.Set("decrypt", Napi::Function::New(env, decryptData));

    return exports;
}

NODE_API_MODULE(secure_enclave, init)
