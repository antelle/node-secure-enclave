#include "auto_release.h"
#include "helpers.h"
#include <Security/Security.h>
#include <napi.h>

constexpr int KEY_SIZE_IN_BITS = 256;

struct DecryptContext;

void decryptFinalizeCallback(Napi::Env env, Napi::Function, DecryptContext *,
                             void *);
using TSFN = Napi::TypedThreadSafeFunction<DecryptContext, void,
                                           decryptFinalizeCallback>;

struct DecryptContext {
    Napi::Promise::Deferred deferred;
    TSFN tsfn;
    CFMutableDictionaryRef queryAttributes;
    CFDataRef encryptedData;
    long authErrorCode;
};

Napi::Value isSupported(const Napi::CallbackInfo &info) {
    return Napi::Boolean::New(info.Env(), isBiometricAuthSupported());
}

Napi::Promise createKeyPair(const Napi::CallbackInfo &info) {
    auto env = info.Env();

    auto deferred = Napi::Promise::Deferred::New(env);

    if (rejectIfNotSupported(deferred)) {
        return deferred.Promise();
    }

    auto_release queryAttributes =
        getKeyQueryAttributesFromArgs(info, deferred);
    if (!queryAttributes) {
        return deferred.Promise();
    }

    auto_release<SecKeyRef> existingPrivateKey = nullptr;
    auto existingKeyStatus = SecItemCopyMatching(
        queryAttributes, reinterpret_cast<CFTypeRef *>(&existingPrivateKey));

    if (existingKeyStatus == errSecSuccess) {
        rejectWithMessageAndProp(
            deferred,
            "A key with this keyTag already exists, please delete it first",
            "keyExists");
        return deferred.Promise();
    } else if (existingKeyStatus != errSecItemNotFound) {
        rejectWithErrorCode(deferred, existingKeyStatus, "SecItemCopyMatching");
        return deferred.Promise();
    }

    auto_release keyTagData = getKeyTagFromArgs(info, deferred);
    if (!keyTagData) {
        return deferred.Promise();
    }

    auto_release keySize = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType,
                                          &KEY_SIZE_IN_BITS);

    auto_release creteKeyAttributes = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    auto_release privateKeyAttrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    CFDictionaryAddValue(privateKeyAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionaryAddValue(privateKeyAttrs, kSecAttrApplicationTag, keyTagData);
    CFDictionaryAddValue(privateKeyAttrs, kSecAttrLabel, keyTagData);

    CFDictionaryAddValue(creteKeyAttributes, kSecAttrKeyType,
                         kSecAttrKeyTypeEC);
    CFDictionaryAddValue(creteKeyAttributes, kSecAttrKeySizeInBits, keySize);
    CFDictionaryAddValue(creteKeyAttributes, kSecPrivateKeyAttrs,
                         privateKeyAttrs);

#ifdef NODE_SECURE_ENCLAVE_BUILD_FOR_TESTING_WITH_REGULAR_KEYCHAIN
    auto_release publicKeyAttrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    CFDictionaryAddValue(publicKeyAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionaryAddValue(publicKeyAttrs, kSecAttrApplicationTag, keyTagData);
    CFDictionaryAddValue(publicKeyAttrs, kSecAttrLabel, keyTagData);

    CFDictionaryAddValue(creteKeyAttributes, kSecPublicKeyAttrs,
                         publicKeyAttrs);
#else
    auto_release access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
        nullptr);
    CFDictionaryAddValue(privateKeyAttrs, kSecAttrAccessControl, access);

    CFDictionaryAddValue(creteKeyAttributes, kSecAttrTokenID,
                         kSecAttrTokenIDSecureEnclave);
#endif

    CFErrorRef error = nullptr;
    auto_release privateKey = SecKeyCreateRandomKey(creteKeyAttributes, &error);
    if (!privateKey) {
        rejectWithCFError(deferred, error, "SecKeyCreateRandomKey");
        return deferred.Promise();
    }

    auto_release publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) {
        rejectWithMessage(deferred, "Can't extract public key");
        return deferred.Promise();
    }

    auto_release publicKeyData =
        SecKeyCopyExternalRepresentation(publicKey, &error);
    if (!publicKeyData) {
        rejectWithCFError(deferred, error, "SecKeyCopyExternalRepresentation");
        return deferred.Promise();
    }

    auto ret = Napi::Object::New(env);
    ret.Set("publicKey", cfDataToBuffer(env, publicKeyData));

    deferred.Resolve(ret);
    return deferred.Promise();
}

Napi::Promise findKeyPair(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    auto deferred = Napi::Promise::Deferred::New(env);

    if (rejectIfNotSupported(deferred)) {
        return deferred.Promise();
    }

    auto_release queryAttributes =
        getKeyQueryAttributesFromArgs(info, deferred);
    if (!queryAttributes) {
        return deferred.Promise();
    }

    auto_release<SecKeyRef> privateKey = nullptr;
    auto status = SecItemCopyMatching(
        queryAttributes, reinterpret_cast<CFTypeRef *>(&privateKey));

    if (status == errSecItemNotFound) {
        deferred.Resolve(env.Null());
        return deferred.Promise();
    } else if (status != errSecSuccess) {
        rejectWithErrorCode(deferred, status, "SecItemCopyMatching");
        return deferred.Promise();
    }

    auto_release publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) {
        rejectWithMessage(deferred, "Can't extract public key");
        return deferred.Promise();
    }

    CFErrorRef error = nullptr;
    auto_release publicKeyData =
        SecKeyCopyExternalRepresentation(publicKey, &error);
    if (!publicKeyData) {
        rejectWithCFError(deferred, error, "SecKeyCopyExternalRepresentation");
        return deferred.Promise();
    }

    auto ret = Napi::Object::New(env);
    ret.Set("publicKey", cfDataToBuffer(env, publicKeyData));

    deferred.Resolve(ret);
    return deferred.Promise();
}

Napi::Promise deleteKeyPair(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    auto deferred = Napi::Promise::Deferred::New(env);

    if (rejectIfNotSupported(deferred)) {
        return deferred.Promise();
    }

    auto_release queryAttributes =
        getKeyQueryAttributesFromArgs(info, deferred);
    if (!queryAttributes) {
        return deferred.Promise();
    }

    auto status = SecItemDelete(queryAttributes);

    if (status == errSecItemNotFound) {
        deferred.Resolve(Napi::Boolean::New(env, false));
        return deferred.Promise();
    } else if (status != errSecSuccess) {
        rejectWithErrorCode(deferred, status, "SecItemDelete");
        return deferred.Promise();
    }

#ifdef NODE_SECURE_ENCLAVE_BUILD_FOR_TESTING_WITH_REGULAR_KEYCHAIN
    CFDictionarySetValue(queryAttributes, kSecAttrKeyClass,
                         kSecAttrKeyClassPublic);
    SecItemDelete(queryAttributes);
#endif

    deferred.Resolve(Napi::Boolean::New(env, true));
    return deferred.Promise();
}

Napi::Promise encryptData(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    auto deferred = Napi::Promise::Deferred::New(env);

    if (rejectIfNotSupported(deferred)) {
        return deferred.Promise();
    }

    auto_release queryAttributes =
        getKeyQueryAttributesFromArgs(info, deferred);
    if (!queryAttributes) {
        return deferred.Promise();
    }

    auto_release decryptedData = getDataFromArgs(info, deferred);
    if (!decryptedData) {
        return deferred.Promise();
    }

    auto_release<SecKeyRef> privateKey = nullptr;
    auto status = SecItemCopyMatching(
        queryAttributes, reinterpret_cast<CFTypeRef *>(&privateKey));

    if (status != errSecSuccess) {
        rejectWithErrorCode(deferred, status, "SecItemCopyMatching");
        return deferred.Promise();
    }

    auto_release publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) {
        rejectWithMessage(deferred, "Can't extract public key");
        return deferred.Promise();
    }

    auto supported = SecKeyIsAlgorithmSupported(
        publicKey, kSecKeyOperationTypeEncrypt,
        kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM);
    if (!supported) {
        rejectWithMessage(deferred, "Algorithm not supported");
        return deferred.Promise();
    }

    CFErrorRef error = nullptr;
    auto_release encryptedData = SecKeyCreateEncryptedData(
        publicKey,
        kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
        decryptedData, &error);
    if (error) {
        rejectWithCFError(deferred, error, "SecKeyCreateEncryptedData");
        return deferred.Promise();
    }

    deferred.Resolve(cfDataToBuffer(env, encryptedData));
    return deferred.Promise();
}

Napi::Promise decryptData(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    auto deferred = Napi::Promise::Deferred::New(env);

    if (rejectIfNotSupported(deferred)) {
        return deferred.Promise();
    }

    // released in decryptFinalizeCallback
    auto queryAttributes = getKeyQueryAttributesFromArgs(info, deferred);
    if (!queryAttributes) {
        return deferred.Promise();
    }

    // released in decryptFinalizeCallback
    auto encryptedData = getDataFromArgs(info, deferred);
    if (!encryptedData) {
        return deferred.Promise();
    }

    auto_release touchIdPrompt = getTouchIdPromptFromArgs(info, deferred);
    if (!touchIdPrompt) {
        return deferred.Promise();
    }

    auto promise = deferred.Promise();

    auto decryptContext = new DecryptContext{
        .deferred = std::move(deferred),
        .queryAttributes = queryAttributes,
        .encryptedData = encryptedData,
        .authErrorCode = -1,
    };

    decryptContext->tsfn = TSFN::New(env, "decryptTSFN", 0, 1, decryptContext);

    authenticateAndDecrypt(touchIdPrompt, queryAttributes, decryptContext);

    return promise;
}

void resumeDecryptWithAuthentication(void *callbackData, long authErrorCode) {
    auto decryptContext = reinterpret_cast<DecryptContext *>(callbackData);

    decryptContext->authErrorCode = authErrorCode;

    decryptContext->tsfn.BlockingCall(decryptContext);
    decryptContext->tsfn.Release();
}

void decryptFinalizeCallback(Napi::Env env, Napi::Function,
                             DecryptContext *decryptContext, void *) {
    auto deferred = std::move(decryptContext->deferred);

    auto authErrorCode = decryptContext->authErrorCode;

    auto_release queryAttributes = decryptContext->queryAttributes;
    auto_release encryptedData = decryptContext->encryptedData;

    delete decryptContext;

    if (authErrorCode) {
        auto err =
            Napi::Error::New(env, "User refused to authenticate with Touch ID");
        err.Set("rejected", Napi::Boolean::New(env, true));
        err.Set("code", Napi::Number::New(env, authErrorCode));
        deferred.Reject(err.Value());
        return;
    }

    auto_release<SecKeyRef> privateKey = nullptr;
    auto status = SecItemCopyMatching(
        queryAttributes, reinterpret_cast<CFTypeRef *>(&privateKey));

    if (status != errSecSuccess) {
        rejectWithErrorCode(deferred, status, "SecItemCopyMatching");
        return;
    }

    auto supported = SecKeyIsAlgorithmSupported(
        privateKey, kSecKeyOperationTypeDecrypt,
        kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM);
    if (!supported) {
        rejectWithMessage(deferred, "Algorithm not supported");
        return;
    }

    CFErrorRef error = nullptr;
    auto_release decryptedData = SecKeyCreateDecryptedData(
        privateKey,
        kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
        encryptedData, &error);
    if (error) {
        rejectWithCFError(deferred, error, "SecKeyCreateDecryptedData");
        return;
    }

    deferred.Resolve(cfDataToBuffer(env, decryptedData));
    return;
}

Napi::Object init(Napi::Env env, Napi::Object exports) {
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor<isSupported>(
        "isSupported", napi_enumerable));

    exports.Set("createKeyPair", Napi::Function::New(env, createKeyPair));
    exports.Set("findKeyPair", Napi::Function::New(env, findKeyPair));
    exports.Set("deleteKeyPair", Napi::Function::New(env, deleteKeyPair));

    exports.Set("encrypt", Napi::Function::New(env, encryptData));
    exports.Set("decrypt", Napi::Function::New(env, decryptData));

    return exports;
}

NODE_API_MODULE(secure_enclave, init)
