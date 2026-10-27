#pragma once
#include "../includes.h"
#include <cstdarg>

namespace svm {

class logs {
  private:
    static constexpr u32 max_msg_length = 128;
    static constexpr u32 max_msg_count = 50000;
    static constexpr u32 max_flush_batch = 128;
    struct log_message {
        u64 id;
        u64 tsc;
        u32 cpu_id;
        char data[max_msg_length];
    };
    struct logger_data {
        char signature[16];
        spin_lock lock;
        u32 msg_start;
        u32 msg_count;
        u64 total_msg_count;
        log_message messages[max_msg_count];
    };
    logger_data log_data;
    static logs instance;
    logs() = default;
    template <typename T> char* custom_itoa(T value, char* result, int base, bool upper = false);
    bool logger_format_copy_char(char* const buffer, char c, u32& idx);
    bool logger_format_copy_str(char* const buffer, char const* const src, u32& idx);
    bool logger_format_copy_wstr(char* const buffer, wchar_t const* const src, u32& idx);
    bool logger_format_copy_unicode(char* const buffer, const UNICODE_STRING* src, u32& idx);
    void format_message_safe(char* buffer, const char* format, va_list args);
    void format_message(char* buffer, const char* format, va_list args);

  public:
    logs(const logs&) = delete;
    logs& operator=(const logs&) = delete;
    static logs* get();
    void initialize();
    void write(const char* format, ...);
    svm::svmroot_error_t flush_logs(svm::pvcpu_t vcpu, u64 buffer_gva, u32& count);
    svm::svmroot_error_t flush_logs(void* buffer, u32& count);
    using message_t = log_message;
};
#define LOG_INFO(fmt, ...) svm::logs::get()->write("[INFO] " fmt, __VA_ARGS__)
#define LOG_ERROR(fmt, ...) svm::logs::get()->write("[ERROR] " fmt, __VA_ARGS__)
#define LOG_DEBUG(fmt, ...) svm::logs::get()->write("[DEBUG] " fmt, __VA_ARGS__)
#define LOG_VMCALL(fmt, ...) svm::logs::get()->write("[VMCALL] " fmt, __VA_ARGS__)
#define LOG_NPT(fmt, ...) svm::logs::get()->write("[NPT] " fmt, __VA_ARGS__)
#define LOG_MEMORY(fmt, ...) svm::logs::get()->write("[MEMORY] " fmt, __VA_ARGS__)
}
