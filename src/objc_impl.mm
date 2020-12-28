#include <LocalAuthentication/LocalAuthentication.h>

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

void promptTouchID() {
    LAContext* context = [[LAContext alloc] init];
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:@"suck my sick"
                      reply:^(BOOL success, NSError * _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (success) {
                NSLog(@"Dick");
            } else {
                NSLog(@"Damn");
            }
        });
    }];
    [context release];
}
