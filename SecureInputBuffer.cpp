#include "SecureInputBuffer.h"
#include <iostream>
#include <cstring>
#include <algorithm>
#include <stdexcept>

// Для системно-зависимых функций
#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
#endif

// Конструктор по умолчанию
SecureInputBuffer::SecureInputBuffer()
        : position(0), echo_enabled(false), mask_char('*') {
    initializeBuffer();
}

// Конструктор с начальным размером
SecureInputBuffer::SecureInputBuffer(size_t initial_size)
        : position(0), echo_enabled(false), mask_char('*') {
    if (initial_size == 0 || initial_size > MAX_BUFFER_SIZE) {
        throw std::invalid_argument("Invalid buffer size");
    }
    buffer.resize(initial_size);
    std::fill(buffer.begin(), buffer.end(), 0);
}