#pragma once
#include <intrin.h>
struct spin_lock {
    void initialize() {
        lock = 0;
    }

    void acquire() {
        while (_InterlockedCompareExchange(&lock, 1, 0))
            _mm_pause();
    }

    bool try_acquire() {
        return _InterlockedCompareExchange(&lock, 1, 0) == 0;
    }

    bool acquire_bounded(unsigned int attempts = 4096) {
        for (unsigned int i = 0; i < attempts; ++i) {
            if (try_acquire())
                return true;
            _mm_pause();
        }
        return false;
    }

    void release() {
        lock = 0;
    }

    volatile long lock;
};
class scoped_spin_lock {
  public:
    scoped_spin_lock(spin_lock& lock) : lock_(lock) {
        lock.acquire();
    }

    ~scoped_spin_lock() {
        lock_.release();
    }

    scoped_spin_lock(scoped_spin_lock const&) = delete;
    scoped_spin_lock& operator=(scoped_spin_lock const&) = delete;

  private:
    spin_lock& lock_;
};
