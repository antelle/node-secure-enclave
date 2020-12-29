#pragma once

#include <Security/Security.h>
#include <napi.h>
#include <string>

bool isBiometricAuthSupported();
void authenticateAndDecrypt(CFStringRef touchIdPrompt, CFMutableDictionaryRef queryAttributes, void *callbackData);

void rejectAsTypeError(Napi::Promise::Deferred &deferred, const std::string &message);
void rejectWithMessage(Napi::Promise::Deferred &deferred, const std::string &message);
void rejectWithMessageAndProp(Napi::Promise::Deferred &deferred, const std::string &message, const std::string &prop);
void rejectWithErrorCode(Napi::Promise::Deferred &deferred, long code, const std::string &op);
void rejectWithCFError(Napi::Promise::Deferred &deferred, CFErrorRef error, const std::string &op);
bool rejectIfNotSupported(Napi::Promise::Deferred &deferred);

CFDataRef getKeyTagFromArgs(const Napi::CallbackInfo &info, Napi::Promise::Deferred &deferred);
CFMutableDictionaryRef getKeyQueryAttributesFromArgs(const Napi::CallbackInfo &info, Napi::Promise::Deferred &deferred);
CFDataRef getDataFromArgs(const Napi::CallbackInfo &info, Napi::Promise::Deferred &deferred);
CFStringRef getTouchIdPromptFromArgs(const Napi::CallbackInfo &info, Napi::Promise::Deferred &deferred);

Napi::Buffer<UInt8> cfDataToBuffer(Napi::Env env, CFDataRef cfData);
