#include "helpers.h"
#include "auto_release.h"
#include <Security/Security.h>

void rejectAsTypeError(Napi::Promise::Deferred& deferred, const std::string& message) {
    auto env = deferred.Env();
    
    auto err = Napi::TypeError::New(env, message);

    deferred.Reject(err.Value());
}

void rejectWithMessage(Napi::Promise::Deferred& deferred, const std::string& message) {
    auto env = deferred.Env();
    
    auto err = Napi::Error::New(env, message);
    
    deferred.Reject(err.Value());
}

void rejectWithMessageAndProp(Napi::Promise::Deferred& deferred,
                              const std::string& message, const std::string& prop) {
    auto env = deferred.Env();
    
    auto err = Napi::Error::New(env, message);
    err.Set(prop, true);
    
    deferred.Reject(err.Value());
}

void rejectWithErrorCode(Napi::Promise::Deferred& deferred, long code, const std::string& op) {
    auto env = deferred.Env();
    
    std::string msg;
    std::string extraProp;
    
    if (code == errSecSuccess) {
        msg = op + ": unknown error without error code";
    } else if (code == errSecItemNotFound) {
        extraProp = "keyNotFound";
        msg = "Key not found in Secure Enclave";
    } else if (code == errSecParam) {
        extraProp = "badParam";
        msg = op + ": bad parameter";
    } else {
        auto_release errorMessage = SecCopyErrorMessageString(code, NULL);
        if (errorMessage) {
            auto str = CFStringGetCStringPtr(errorMessage, kCFStringEncodingUTF8);
            msg = op + ": " + str;
        } else {
            msg = op + ": error code " + std::to_string(code);
        }
    }
    
    auto err = Napi::Error::New(env, msg);
    err.Set("code", Napi::Number::New(env, code));
    if (!extraProp.empty()) {
        err.Set(extraProp, Napi::Boolean::New(env, true));
    }
    deferred.Reject(err.Value());
}

void rejectWithCFError(Napi::Promise::Deferred& deferred, CFErrorRef error, const std::string& op) {
    auto code = CFErrorGetCode(error);
    rejectWithErrorCode(deferred, code, op);
}

bool rejectIfNotSupported(Napi::Promise::Deferred& deferred) {
    if (!isBiometricAuthSupported()) {
        rejectWithMessageAndProp(deferred, "Biometric auth is not supported", "notSupported");
        return true;
    }
    return false;
}

auto_release<CFDataRef> getKeyTagFromArgs(const Napi::CallbackInfo& info, Napi::Promise::Deferred& deferred) {
    if (info.Length() != 1) {
        rejectAsTypeError(deferred, "Expected exactly one argument");
        return nullptr;
    }

    if (!info[0].IsObject()) {
        rejectAsTypeError(deferred, "options is not an object");
        return nullptr;
    }

    auto arg = info[0].ToObject();

    if (!arg.Has("keyTag")) {
        rejectAsTypeError(deferred, "keyTag property is missing");
        return nullptr;
    }

    auto keyTagProp = arg.Get("keyTag");
    if (!keyTagProp.IsString()) {
        rejectAsTypeError(deferred, "keyTag is not a string");
        return nullptr;
    }
    auto keyTag = keyTagProp.As<Napi::String>();

    auto keyTagStr = keyTag.Utf8Value();
    if (keyTagStr.length() == 0) {
        rejectAsTypeError(deferred, "keyTag cannot be empty");
        return nullptr;
    }

    return CFDataCreate(kCFAllocatorDefault,
                          reinterpret_cast<const UInt8*>(keyTagStr.c_str()), keyTagStr.length());
}

auto_release<CFMutableDictionaryRef> getKeyQueryAttributesFromArgs(const Napi::CallbackInfo& info,
                                                                   Napi::Promise::Deferred& deferred) {
    auto_release keyTagData = getKeyTagFromArgs(info, deferred);
    if (!keyTagData) {
        return nullptr;
    }

    auto queryAttributes = CFDictionaryCreateMutable(kCFAllocatorDefault,
        0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionaryAddValue(queryAttributes, kSecClass, kSecClassKey);
    CFDictionaryAddValue(queryAttributes, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionaryAddValue(queryAttributes, kSecAttrKeyType, kSecAttrKeyTypeEC);
    CFDictionaryAddValue(queryAttributes, kSecAttrApplicationTag, keyTagData);
    CFDictionaryAddValue(queryAttributes, kSecReturnRef, kCFBooleanTrue);
#ifndef NODE_SECURE_ENCLAVE_BUILD_FOR_TESTING_WITH_REGULAR_KEYCHAIN
    CFDictionaryAddValue(queryAttributes, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
#endif

    return queryAttributes;
}

auto_release<SecKeyRef> getPrivateKeyFromArgs(const Napi::CallbackInfo& info, Napi::Promise::Deferred& deferred) {
    auto_release queryAttributes = getKeyQueryAttributesFromArgs(info, deferred);
    if (!queryAttributes) {
        return nullptr;
    }

    SecKeyRef privateKey = nullptr;
    auto status = SecItemCopyMatching(queryAttributes,
        const_cast<CFTypeRef*>(reinterpret_cast<const CFTypeRef*>(&privateKey)));

    if (status != errSecSuccess) {
        rejectWithErrorCode(deferred, status, "SecItemCopyMatching");
        return nullptr;
    }

    return privateKey;
}

auto_release<CFDataRef> getDataFromArgs(const Napi::CallbackInfo& info, Napi::Promise::Deferred& deferred) {
    auto object = info[0].ToObject();

    if (!object.Has("data")) {
        rejectAsTypeError(deferred, "data property is missing");
        return nullptr;
    }

    auto dataProp = object.Get("data");
    if (!dataProp.IsBuffer()) {
        rejectAsTypeError(deferred, "data is not a buffer");
        return nullptr;
    }

    auto buffer = dataProp.As<Napi::Buffer<UInt8>>();
    if (buffer.ByteLength() == 0) {
        rejectAsTypeError(deferred, "data cannot be empty");
        return nullptr;
    }

    return CFDataCreate(kCFAllocatorDefault, buffer.Data(), buffer.ByteLength());
}

Napi::Buffer<UInt8> cfDataToBuffer(Napi::Env env, CFDataRef cfData) {
    auto length = CFDataGetLength(cfData);
    return Napi::Buffer<UInt8>::Copy(env, CFDataGetBytePtr(cfData), length);
}
