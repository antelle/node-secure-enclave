#include "helpers.h"
#include "auto_release.h"
#include <Security/Security.h>

Napi::Value throwErrorWithCode(Napi::Env env, long code, const std::string& op) {
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
    err.ThrowAsJavaScriptException();
    return env.Null();
}

Napi::Value throwErrorWithCFError(Napi::Env env, CFErrorRef error, const std::string& op) {
    auto code = CFErrorGetCode(error);
    return throwErrorWithCode(env, code, op);
}

Napi::Value throwNotSupportedError(Napi::Env env) {
    auto err = Napi::Error::New(env, "Biometric auth is not supported");
    err.Set("notSupported", Napi::Boolean::New(env, true));
    err.ThrowAsJavaScriptException();
    return env.Null();
}

auto_release<CFDataRef> getKeyTagFromArgs(const Napi::CallbackInfo& info) {
    auto env = info.Env();

    if (info.Length() != 1) {
        Napi::TypeError::New(env, "Expected exactly one argument").ThrowAsJavaScriptException();
        return nullptr;
    }

    if (!info[0].IsObject()) {
        Napi::TypeError::New(env, "options is not an object").ThrowAsJavaScriptException();
        return nullptr;
    }

    auto arg = info[0].ToObject();

    if (!arg.Has("keyTag")) {
        Napi::TypeError::New(env, "keyTag property is missing").ThrowAsJavaScriptException();
        return nullptr;
    }

    auto keyTagProp = arg.Get("keyTag");
    if (!keyTagProp.IsString()) {
        Napi::TypeError::New(env, "keyTag is not a string").ThrowAsJavaScriptException();
        return nullptr;
    }
    auto keyTag = keyTagProp.As<Napi::String>();

    auto keyTagStr = keyTag.Utf8Value();
    if (keyTagStr.length() == 0) {
        Napi::TypeError::New(env, "keyTag cannot be empty").ThrowAsJavaScriptException();
        return nullptr;
    }

    return CFDataCreate(kCFAllocatorDefault,
                          reinterpret_cast<const UInt8*>(keyTagStr.c_str()), keyTagStr.length());
}

auto_release<CFMutableDictionaryRef> getKeyQueryAttributesFromArgs(const Napi::CallbackInfo& info) {
    auto_release keyTagData = getKeyTagFromArgs(info);
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

auto_release<SecKeyRef> getPrivateKeyFromArgs(const Napi::CallbackInfo& info) {
    auto_release queryAttributes = getKeyQueryAttributesFromArgs(info);
    if (!queryAttributes) {
        return nullptr;
    }

    SecKeyRef privateKey = nullptr;
    auto status = SecItemCopyMatching(queryAttributes,
        const_cast<CFTypeRef*>(reinterpret_cast<const CFTypeRef*>(&privateKey)));

    if (status != errSecSuccess) {
        throwErrorWithCode(info.Env(), status, "SecItemCopyMatching");
        return nullptr;
    }

    return privateKey;
}

auto_release<CFDataRef> getDataFromArgs(const Napi::CallbackInfo& info) {
    auto env = info.Env();

    auto object = info[0].ToObject();

    if (!object.Has("data")) {
        Napi::TypeError::New(env, "data property is missing").ThrowAsJavaScriptException();
        return nullptr;
    }

    auto dataProp = object.Get("data");
    if (!dataProp.IsBuffer()) {
        Napi::TypeError::New(env, "data is not a buffer").ThrowAsJavaScriptException();
        return nullptr;
    }

    auto buffer = dataProp.As<Napi::Buffer<UInt8>>();
    if (buffer.ByteLength() == 0) {
        Napi::TypeError::New(env, "data cannot be empty").ThrowAsJavaScriptException();
        return nullptr;
    }

    return CFDataCreate(kCFAllocatorDefault, buffer.Data(), buffer.ByteLength());
}

Napi::Buffer<UInt8> cfDataToBuffer(Napi::Env env, CFDataRef cfData) {
    auto length = CFDataGetLength(cfData);
    return Napi::Buffer<UInt8>::Copy(env, CFDataGetBytePtr(cfData), length);
}
