#pragma once

#include <CoreFoundation/CoreFoundation.h>

template<typename T>
class auto_release {
private:
    T resource_ = nullptr;
    auto_release(const auto_release&) = delete;

public:
    auto_release(T resource): resource_(resource) {
    }
    
    auto_release(auto_release&& other) noexcept: resource_(other.resource_) {
        other.resource_ = nullptr;
    }

    ~auto_release() {
        if (resource_) {
            CFRelease(resource_);
            resource_ = nullptr;
        }
    }

    operator T() const {
        return resource_;
    }
};
