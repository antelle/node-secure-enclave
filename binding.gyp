{
  "targets": [
    {
      "target_name": "secure_enclave",
      "sources": [
        "src/addon.cpp",
        "src/auto_release.h",
        "src/helpers.h",
        "src/helpers.cpp",
        "src/objc_impl.mm",
      ],
      "include_dirs": ["<!(node -p \"require('node-addon-api').include_dir\")"],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
      "link_settings": {
        "libraries": [
          "$(SDKROOT)/System/Library/Frameworks/AppKit.framework",
          "$(SDKROOT)/System/Library/Frameworks/Security.framework",
          "$(SDKROOT)/System/Library/Frameworks/LocalAuthentication.framework",
        ],
      },
      "xcode_settings": {
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "10.14",
        "CLANG_CXX_LANGUAGE_STANDARD": "gnu++17"
      },
      "variables": {
        "NODE_SECURE_ENCLAVE_BUILD_FOR_TESTING_WITH_REGULAR_KEYCHAIN%": "0"
      },
      "conditions": [
        ["NODE_SECURE_ENCLAVE_BUILD_FOR_TESTING_WITH_REGULAR_KEYCHAIN==1",
          { "defines": [ "NODE_SECURE_ENCLAVE_BUILD_FOR_TESTING_WITH_REGULAR_KEYCHAIN" ] }]
      ]
    }
  ]
}
