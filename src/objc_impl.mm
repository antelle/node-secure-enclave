#include <LocalAuthentication/LocalAuthentication.h>

void resumeDecryptWithAuthentication(void *callbackData, long authErrorCode);

bool isBiometricAuthSupported() {
    static bool checked = false;
    static bool supported = false;
    if (checked) {
        return supported;
    }
    LAContext *context = [[LAContext alloc] init];
    NSError *error = nil;
    LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
    if (@available(macOS 10.15, *)) {
        policy = LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch;
    }
    supported = [context canEvaluatePolicy:policy error:&error];
    if (!supported && context.biometryType == LABiometryTypeTouchID && error && error.code == LAErrorBiometryLockout) {
        supported = true;
    }
#ifdef NODE_SECURE_ENCLAVE_BUILD_FOR_TESTING_WITH_REGULAR_KEYCHAIN
    supported = true;
#endif
    [context release];
    checked = true;
    return supported;
}

void tryAuthenticate(LAContext *context, bool useBiometrics, CFStringRef touchIdPrompt,
                     CFMutableDictionaryRef queryAttributes, void *callbackData, bool retryOnLockout) {
    CFRetain(touchIdPrompt);
    LAPolicy policy = LAPolicyDeviceOwnerAuthentication;
    if (useBiometrics) {
        if (@available(macOS 10.15, *)) {
            policy = LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch;
        } else {
            policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
        }
    }
    context.localizedFallbackTitle = @"";
    [context evaluatePolicy:policy
            localizedReason:(NSString *)touchIdPrompt
                      reply:^(BOOL success, NSError *_Nullable error) {
                        long errorCode = 0;
                        if (!success) {
                            errorCode = error ? error.code ? error.code : 1 : 2;
                        }
                        if (useBiometrics && errorCode == LAErrorBiometryLockout && retryOnLockout) {
                            dispatch_async(dispatch_get_main_queue(), ^{
                              tryAuthenticate(context, false, touchIdPrompt, queryAttributes, callbackData, false);
                              CFRelease(touchIdPrompt);
                            });
                        } else if (!useBiometrics && success) {
                            dispatch_async(dispatch_get_main_queue(), ^{
                              tryAuthenticate(context, true, touchIdPrompt, queryAttributes, callbackData, false);
                              CFRelease(touchIdPrompt);
                            });
                        } else {
                            CFRelease(touchIdPrompt);
                            resumeDecryptWithAuthentication(callbackData, errorCode);
                        }
                      }];
}

void authenticateAndDecrypt(CFStringRef touchIdPrompt, CFMutableDictionaryRef queryAttributes, void *callbackData) {
#ifdef NODE_SECURE_ENCLAVE_BUILD_FOR_TESTING_WITH_REGULAR_KEYCHAIN
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
      // we don't need this thread, it's here for life-like tests
      resumeDecryptWithAuthentication(callbackData, 0);
    });
#else
    LAContext *context = [[LAContext alloc] init];
    CFDictionaryAddValue(queryAttributes, kSecUseAuthenticationContext, context);
    [context release];

    NSError *error = nil;
    LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
    if (@available(macOS 10.15, *)) {
        policy = LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch;
    }
    [context canEvaluatePolicy:policy error:&error];

    bool useBiometrics = error && error.code == LAErrorBiometryLockout;
    tryAuthenticate(context, useBiometrics, touchIdPrompt, queryAttributes, callbackData, useBiometrics);
#endif
}
