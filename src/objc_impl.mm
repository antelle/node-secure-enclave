#include <LocalAuthentication/LocalAuthentication.h>

void resumeDecryptWithAuthentication(void* callbackData, long authErrorCode);

bool isBiometricAuthSupported() {
    static bool checked = false;
    static bool supported = false;
    if (checked) {
        return supported;
    }
    LAContext* context = [[LAContext alloc] init];
    supported = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];
#ifdef NODE_SECURE_ENCLAVE_BUILD_FOR_TESTING_WITH_REGULAR_KEYCHAIN
    supported = true;
#endif
    [context release];
    checked = true;
    return supported;
}

void authenticateAndDecrypt(CFStringRef touchIdPrompt,
                           CFMutableDictionaryRef queryAttributes,
                           void* callbackData) {
#ifdef NODE_SECURE_ENCLAVE_BUILD_FOR_TESTING_WITH_REGULAR_KEYCHAIN
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        // we don't need this thread, it's here for life-like tests
        resumeDecryptWithAuthentication(callbackData, 0);
    });
#else
    LAContext* context = [[LAContext alloc] init];
    CFDictionaryAddValue(queryAttributes, kSecUseAuthenticationContext, context);
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:(NSString*)touchIdPrompt
                      reply:^(BOOL success, NSError* _Nullable error) {
        long errorCode = success ? 0 : (error && error.code || -1);
        resumeDecryptWithAuthentication(callbackData, errorCode);
    }];
    [context release];
#endif
}
