#pragma once

#include "auto_release.h"
#include <napi.h>
#include <Security/Security.h>
#include <string>

extern bool isBiometricAuthSupported();

Napi::Value throwErrorWithCode(Napi::Env env, long code, const std::string& op);
Napi::Value throwErrorWithCFError(Napi::Env env, CFErrorRef error, const std::string& op);
Napi::Value throwNotSupportedError(Napi::Env env);

auto_release<CFDataRef> getKeyTagFromArgs(const Napi::CallbackInfo& info);
auto_release<CFMutableDictionaryRef> getKeyQueryAttributesFromArgs(const Napi::CallbackInfo& info);
auto_release<SecKeyRef> getPrivateKeyFromArgs(const Napi::CallbackInfo& info);
auto_release<CFDataRef> getDataFromArgs(const Napi::CallbackInfo& info);

Napi::Buffer<UInt8> cfDataToBuffer(Napi::Env env, CFDataRef cfData);
