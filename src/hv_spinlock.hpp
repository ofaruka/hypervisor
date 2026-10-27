#pragma once

// Writer-preferred reader-writer spinlock for root-mode exit handlers.
//
// Why this exists:
// The vmmcall/vmcall dispatcher mutates shared state (hook table, per-vcpu
// nested page tables and live VMCB/VMCS fields of *other* processors). When
// two processors run handlers concurrently - e.g. one worker thread installs
// a hook while another issues hide/get_physical_address vmmcalls - they can
// corrupt each other's state and fault in root mode. Because the host IDT is
// a copy of the guest IDT, any root-mode fault lands in the guest's
// KiPageFault with a root-mode RIP/RSP and kills the machine
// (0x1AA EXCEPTION_ON_INVALID_STACK, or a frozen boot without a debugger).
//
// Why reader-writer and not a single global lock:
// NPT/EPT violation handlers run on the hot path of every hooked dispatch
// (storage and network drivers fire them constantly during boot). A single
// exclusive lock serializes all of that across all CPUs and the machine
// crawls until a watchdog NMI kills it (observed as a 30-40s boot stall
// followed by 0x80 NMI_HARDWARE_FAILURE). Violation handlers only mutate
// their own vcpu's VMCB/VMCS; they merely need to be excluded against
// writers (hook install/remove/hide), not against each other.
//
// Rules:
//  - Writers (exclusive): vmmcall/vmcall handlers (install/remove/hide/etc).
//  - Readers (shared):    NPT/EPT violation handlers.
//  - Safe per-CPU: while a processor is in root mode its guest cannot run,
//    so the same CPU can never re-enter a guarded section.
//  - Handlers must not wait on remote CPUs while holding the lock in either
//    mode; readers must never block so writers can always drain them.

class hv_spinlock {
public:
    static void acquire_shared() {
        for (;;) {
            while (writer_active || writers_waiting) {
                _mm_pause();
            }

            InterlockedIncrement(&readers);

            if (!writer_active && !writers_waiting) {
                return;
            }

            InterlockedDecrement(&readers);
        }
    }

    static void release_shared() {
        InterlockedDecrement(&readers);
    }

    static void acquire_exclusive() {
        InterlockedIncrement(&writers_waiting);

        while (_InterlockedCompareExchange(&writer_active, 1, 0) != 0) {
            _mm_pause();
        }

        while (readers != 0) {
            _mm_pause();
        }

        InterlockedDecrement(&writers_waiting);
    }

    static void release_exclusive() {
        _InterlockedExchange(&writer_active, 0);
    }

private:
    inline static volatile LONG readers = 0;
    inline static volatile LONG writer_active = 0;
    inline static volatile LONG writers_waiting = 0;
};

class hv_shared_lock_guard {
public:
    hv_shared_lock_guard() { hv_spinlock::acquire_shared(); }
    ~hv_shared_lock_guard() { hv_spinlock::release_shared(); }

    hv_shared_lock_guard(const hv_shared_lock_guard&) = delete;
    hv_shared_lock_guard& operator=(const hv_shared_lock_guard&) = delete;
};

class hv_exclusive_lock_guard {
public:
    hv_exclusive_lock_guard() { hv_spinlock::acquire_exclusive(); }
    ~hv_exclusive_lock_guard() { hv_spinlock::release_exclusive(); }

    hv_exclusive_lock_guard(const hv_exclusive_lock_guard&) = delete;
    hv_exclusive_lock_guard& operator=(const hv_exclusive_lock_guard&) = delete;
};
