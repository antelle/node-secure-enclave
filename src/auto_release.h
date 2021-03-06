#pragma once

#include <CoreFoundation/CoreFoundation.h>

template <typename T> class auto_release {
  private:
    T resource_ = nullptr;
    auto_release(const auto_release &) = delete;

  public:
    auto_release(T resource) : resource_(resource) {}

    auto_release(auto_release &&other) noexcept : resource_(other.resource_) { other.resource_ = nullptr; }

    ~auto_release() {
        if (resource_) {
            CFRelease(resource_);
            resource_ = nullptr;
        }
    }

    operator T() const { return resource_; }

    T *operator&() { return &resource_; }

    CFTypeRef *cfTypeRef() {
        // in the official docs it's just a C-style cast, so...
        return const_cast<CFTypeRef *>(reinterpret_cast<const CFTypeRef *>(&resource_));
    }
};
