#include <LocalAuthentication/LocalAuthentication.h>

void resumeDecryptAfterTouchId(bool success, long errorCode);

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

void promptTouchId(CFStringRef touchIdPrompt, CFMutableDictionaryRef queryAttributes) {
    LAContext* context = [[LAContext alloc] init];
    CFDictionaryAddValue(queryAttributes, kSecUseAuthenticationContext, context);
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:(NSString*)touchIdPrompt
                      reply:^(BOOL success, NSError* _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            resumeDecryptAfterTouchId(success, error ? error.code : 0);
        });
    }];
    [context release];
}
