#include "logger.hpp"

namespace svm {

logs logs::instance;

logs* logs::get() {
    return &instance;
}

void logs::initialize() {
    auto& l = log_data;
    memcpy(l.signature, "hvloggerhvlogger", 16);
    l.lock.initialize();
    l.msg_start = 0;
    l.msg_count = 0;
    l.total_msg_count = 0;
    write("Logger initialized\n");
}

template <typename T>

char* logs::custom_itoa(T value, char* result, int base, bool upper) {
    if (base < 2 || base > 36) {
        *result = '\0';
        return result;
    }

    char *ptr = result, *ptr1 = result, tmp_char;
    T tmp_value;
    const char* digits_upper = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char* digits_lower = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz";
    do {
        tmp_value = value;
        value /= base;
        *ptr++ = (upper ? digits_upper : digits_lower)[35 + (tmp_value - value * base)];
    } while (value);

    if (tmp_value < 0)
        *ptr++ = '-';
    *ptr-- = '\0';

    while (ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr-- = *ptr1;
        *ptr1++ = tmp_char;
    }

    return result;
}

bool logs::logger_format_copy_char(char* const buffer, char c, u32& idx) {
    if (idx >= max_msg_length - 1) {
        buffer[max_msg_length - 1] = '\0';
        return true;
    }

    buffer[idx++] = c;
    return idx >= max_msg_length - 1;
}

bool logs::logger_format_copy_str(char* const buffer, char const* const src, u32& idx) {
    if (!src) {
        return logger_format_copy_str(buffer, "(null)", idx);
    }

    for (u32 i = 0; src[i]; ++i) {
        if (logger_format_copy_char(buffer, src[i], idx)) {
            return true;
        }
    }

    return false;
}

bool logs::logger_format_copy_wstr(char* const buffer, wchar_t const* const src, u32& idx) {
    if (!src) {
        return logger_format_copy_str(buffer, "(null)", idx);
    }

    for (u32 i = 0; src[i]; ++i) {
        char c = src[i] >= 0x20 && src[i] <= 0x7E ? static_cast<char>(src[i]) : '?';
        if (logger_format_copy_char(buffer, c, idx)) {
            return true;
        }
    }

    return false;
}

bool logs::logger_format_copy_unicode(char* const buffer, const UNICODE_STRING* src, u32& idx) {
    if (!src || !src->Buffer) {
        return logger_format_copy_str(buffer, "(null)", idx);
    }

    u32 chars = src->Length / sizeof(wchar_t);
    for (u32 i = 0; i < chars; ++i) {
        char c = src->Buffer[i] >= 0x20 && src->Buffer[i] <= 0x7E ? static_cast<char>(src->Buffer[i]) : '?';
        if (logger_format_copy_char(buffer, c, idx)) {
            return true;
        }
    }

    return false;
}

void logs::format_message_safe(char* buffer, const char* format, va_list args) {
    u32 buffer_idx = 0;
    u32 format_idx = 0;

    while (true) {
        char c = format[format_idx++];
        if (!c)
            break;

        if (c != '%') {
            if (logger_format_copy_char(buffer, c, buffer_idx))
                break;
            continue;
        }

        if (format[format_idx] == '%') {
            format_idx++;
            if (logger_format_copy_char(buffer, '%', buffer_idx))
                break;
            continue;
        }

        while (format[format_idx] == '-' || format[format_idx] == '+' || format[format_idx] == ' ' ||
               format[format_idx] == '#' || format[format_idx] == '0') {
            format_idx++;
        }

        while (format[format_idx] >= '0' && format[format_idx] <= '9') {
            format_idx++;
        }

        if (format[format_idx] == '.') {
            format_idx++;
            if (format[format_idx] == '*') {
                va_arg(args, int);
                format_idx++;
            } else {
                while (format[format_idx] >= '0' && format[format_idx] <= '9')
                    format_idx++;
            }
        }

        enum length_t { length_default, length_long, length_long_long, length_size };
        length_t length = length_default;
        bool wide = false;

        if (format[format_idx] == 'w') {
            wide = true;
            format_idx++;
        } else if (format[format_idx] == 'l') {
            length = length_long;
            format_idx++;
            if (format[format_idx] == 'l') {
                length = length_long_long;
                format_idx++;
            }
        } else if (format[format_idx] == 'z') {
            length = length_size;
            format_idx++;
        } else if (format[format_idx] == 'I' &&
                   format[format_idx + 1] == '6' &&
                   format[format_idx + 2] == '4') {
            length = length_long_long;
            format_idx += 3;
        }

        char spec = format[format_idx++];
        char num_buffer[128];

        switch (spec) {
        case 's':
            if (wide) {
                if (logger_format_copy_wstr(buffer, va_arg(args, wchar_t const*), buffer_idx))
                    return;
            } else if (logger_format_copy_str(buffer, va_arg(args, char const*), buffer_idx)) {
                return;
            }
            break;
        case 'S':
            if (logger_format_copy_wstr(buffer, va_arg(args, wchar_t const*), buffer_idx))
                return;
            break;
        case 'Z':
            if (wide) {
                if (logger_format_copy_unicode(buffer, va_arg(args, const UNICODE_STRING*), buffer_idx))
                    return;
            } else if (logger_format_copy_str(buffer, va_arg(args, char const*), buffer_idx)) {
                return;
            }
            break;
        case 'd':
        case 'i':
            if (length == length_long_long) {
                if (logger_format_copy_str(buffer, custom_itoa(va_arg(args, long long), num_buffer, 10), buffer_idx))
                    return;
            } else if (length == length_long) {
                if (logger_format_copy_str(buffer, custom_itoa(va_arg(args, long), num_buffer, 10), buffer_idx))
                    return;
            } else if (length == length_size) {
                if (logger_format_copy_str(buffer, custom_itoa((long long)va_arg(args, size_t), num_buffer, 10), buffer_idx))
                    return;
            } else if (logger_format_copy_str(buffer, custom_itoa(va_arg(args, int), num_buffer, 10), buffer_idx)) {
                return;
            }
            break;
        case 'u':
            if (length == length_long_long) {
                if (logger_format_copy_str(buffer, custom_itoa(va_arg(args, unsigned long long), num_buffer, 10), buffer_idx))
                    return;
            } else if (length == length_long) {
                if (logger_format_copy_str(buffer, custom_itoa(va_arg(args, unsigned long), num_buffer, 10), buffer_idx))
                    return;
            } else if (length == length_size) {
                if (logger_format_copy_str(buffer, custom_itoa(va_arg(args, size_t), num_buffer, 10), buffer_idx))
                    return;
            } else if (logger_format_copy_str(buffer, custom_itoa(va_arg(args, unsigned int), num_buffer, 10), buffer_idx)) {
                return;
            }
            break;
        case 'x':
        case 'X': {
            u64 value = 0;
            if (length == length_long_long)
                value = va_arg(args, unsigned long long);
            else if (length == length_long)
                value = va_arg(args, unsigned long);
            else if (length == length_size)
                value = va_arg(args, size_t);
            else
                value = va_arg(args, unsigned int);

            if (logger_format_copy_str(buffer, "0x", buffer_idx) ||
                logger_format_copy_str(buffer, custom_itoa(value, num_buffer, 16, spec == 'X'), buffer_idx))
                return;
            break;
        }
        case 'p':
            if (logger_format_copy_str(buffer, "0x", buffer_idx) ||
                logger_format_copy_str(buffer, custom_itoa((u64)va_arg(args, void*), num_buffer, 16, true), buffer_idx))
                return;
            break;
        case 'c':
            if (logger_format_copy_char(buffer, static_cast<char>(va_arg(args, int)), buffer_idx))
                return;
            break;
        default:
            if (logger_format_copy_char(buffer, '%', buffer_idx) ||
                logger_format_copy_char(buffer, spec, buffer_idx))
                return;
            break;
        }
    }

    buffer[buffer_idx] = '\0';
}

void logs::format_message(char* buffer, const char* format, va_list args) {
    u32 buffer_idx = 0;
    u32 format_idx = 0;
    bool specifying = false;

    while (true) {
        auto const c = format[format_idx++];

        if (c == '\0')
            break;
        if (c == '%') {
            specifying = true;
            continue;
        }

        if (!specifying) {
            buffer[buffer_idx++] = c;

            if (buffer_idx >= max_msg_length - 1)
                break;
            specifying = false;
            continue;
        }

        char num_buffer[128];

        switch (c) {
        case 's': {
            if (logger_format_copy_str(buffer, va_arg(args, char const*), buffer_idx))
                return;
            break;
        }
        case 'd':
        case 'i': {
            if (logger_format_copy_str(buffer, custom_itoa(va_arg(args, int), num_buffer, 10), buffer_idx))
                return;
            break;
        }
        case 'x': {
            if (logger_format_copy_str(buffer, "0x", buffer_idx))
                return;
            if (logger_format_copy_str(buffer, custom_itoa(va_arg(args, u64), num_buffer, 16, false), buffer_idx))
                return;
            break;
        }
        case 'X': {
            if (logger_format_copy_str(buffer, "0x", buffer_idx))
                return;
            if (logger_format_copy_str(buffer, custom_itoa(va_arg(args, u64), num_buffer, 16, true), buffer_idx))
                return;
            break;
        }
        case 'p': {
            if (logger_format_copy_str(buffer, "0x", buffer_idx))
                return;
            if (logger_format_copy_str(buffer, custom_itoa((u64)va_arg(args, void*), num_buffer, 16, true), buffer_idx))
                return;
            break;
        }
        }

        specifying = false;
    }

    buffer[buffer_idx] = '\0';
}

void logs::write(const char* format, ...) {
    char str[max_msg_length];
    va_list args;
    va_start(args, format);
    format_message_safe(str, format, args);
    va_end(args);
    if (!log_data.lock.acquire_bounded())
        return;

    auto& msg = log_data.messages[(log_data.msg_start + log_data.msg_count) % max_msg_count];

    if (log_data.msg_count < max_msg_count)
        log_data.msg_count++;
    else
        log_data.msg_start = (log_data.msg_start + 1) % max_msg_count;
    memset(msg.data, 0, max_msg_length);

    for (size_t i = 0; (i < max_msg_length - 1) && str[i]; ++i)
        msg.data[i] = str[i];
    msg.id = ++log_data.total_msg_count;
    msg.tsc = __rdtsc();
    msg.cpu_id = KeGetCurrentProcessorNumber();
    log_data.lock.release();
}

svm::svmroot_error_t logs::flush_logs(svm::pvcpu_t vcpu, u64 buffer_gva, u32& count) {
    if (count == 0) {
        return svm::svmroot_error_t::error_failed;
    }

    if (!log_data.lock.acquire_bounded()) {
        count = 0;
        return svm::svmroot_error_t::error_failed;
    }

    count = min(min(count, log_data.msg_count), max_flush_batch);

    if (count > 0) {
        auto start = reinterpret_cast<u8*>(&log_data.messages[log_data.msg_start]);
        auto first_chunk_count = min(max_msg_count - log_data.msg_start, count);
        auto size = first_chunk_count * sizeof(log_message);

        for (size_t bytes_copied = 0; bytes_copied < size;) {
            size_t curr_size = 0;
            auto curr_hva = page_table::get()->gva_to_hva(vcpu->guest_vmcb.state_save_area.cr3,
                                                          buffer_gva + bytes_copied, curr_size);
            if (!curr_hva) {
                log_data.lock.release();
                return svm::svmroot_error_t::error_failed;
            }

            auto copy_size = min(size - bytes_copied, curr_size);
            memcpy(curr_hva, start + bytes_copied, copy_size);
            bytes_copied += copy_size;
        }

        if (first_chunk_count < count) {
            buffer_gva += size;
            start = reinterpret_cast<u8*>(&log_data.messages[0]);
            size = (count - first_chunk_count) * sizeof(log_message);

            for (size_t bytes_copied = 0; bytes_copied < size;) {
                size_t curr_size = 0;
                auto curr_hva = page_table::get()->gva_to_hva(vcpu->guest_vmcb.state_save_area.cr3,
                                                              buffer_gva + bytes_copied, curr_size);
                if (!curr_hva) {
                    log_data.lock.release();
                    return svm::svmroot_error_t::error_failed;
                }

                auto copy_size = min(size - bytes_copied, curr_size);
                memcpy(curr_hva, start + bytes_copied, copy_size);
                bytes_copied += copy_size;
            }
        }

        log_data.msg_count -= count;
        log_data.msg_start = (log_data.msg_start + count) % max_msg_count;
    }

    log_data.lock.release();
    return svm::svmroot_error_t::error_success;
}

svm::svmroot_error_t logs::flush_logs(void* buffer, u32& count) {
    if (!buffer || count == 0) {
        return svm::svmroot_error_t::error_failed;
    }

    if (!log_data.lock.acquire_bounded()) {
        count = 0;
        return svm::svmroot_error_t::error_failed;
    }

    count = min(min(count, log_data.msg_count), max_flush_batch);

    if (count > 0) {
        auto out = static_cast<u8*>(buffer);
        auto start = reinterpret_cast<u8*>(&log_data.messages[log_data.msg_start]);
        auto first_chunk_count = min(max_msg_count - log_data.msg_start, count);
        auto size = first_chunk_count * sizeof(log_message);
        RtlCopyMemory(out, start, size);

        if (first_chunk_count < count) {
            out += size;
            start = reinterpret_cast<u8*>(&log_data.messages[0]);
            size = (count - first_chunk_count) * sizeof(log_message);
            RtlCopyMemory(out, start, size);
        }

        log_data.msg_count -= count;
        log_data.msg_start = (log_data.msg_start + count) % max_msg_count;
    }

    log_data.lock.release();
    return svm::svmroot_error_t::error_success;
}
}
