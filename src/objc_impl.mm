#include <LocalAuthentication/LocalAuthentication.h>

bool isBiometricAuthSupported() {
    static bool checked = false;
    static bool supported = false;
    if (checked) {
        return supported;
    }
    LAContext *context = [[LAContext alloc] init];
    supported = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];
    [context release];
    checked = true;
    return supported;
}
