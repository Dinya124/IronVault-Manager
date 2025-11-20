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


// Основной метод чтения из stdin
bool SecureInputBuffer::readFromStdin(bool hide_input) {
    return readFromStdinWithCallback(nullptr, hide_input);
}

// Чтение с callback для прогресса
bool SecureInputBuffer::readFromStdinWithCallback(const std::function<void(size_t, size_t)>& callback, bool hide_input) {
    clear();

    // Сохраняем текущие настройки терминала
    bool original_echo = setStdinEcho(false);

    try {
        std::cout.flush();

        while (true) {
            int ch = getChar();
            if (ch == EOF) {
                break;
            }

            char c = static_cast<char>(ch);

            // Обработка специальных символов
            if (c == ENTER) {
                std::cout << std::endl;
                break;
            }
            else if (c == BACKSPACE) {
                handleBackspace();
            }
            else if (c == CTRL_C || c == CTRL_D) {
                secureClear();
                setStdinEcho(original_echo);
                return false; // Прервано пользователем
            }
            else if (isValidCharacter(c)) {
                handleCharacter(c, hide_input);
            }

            // Вызываем callback если предоставлен
            if (callback) {
                callback(position, buffer.size());
            }

            // Проверяем не превысили ли максимальный размер
            if (exceedsMaxSize()) {
                secureClear();
                throw std::runtime_error("Input exceeds maximum allowed size");
            }
        }

        // Восстанавливаем настройки терминала
        setStdinEcho(original_echo);

        return true;

    } catch (const std::exception& e) {
        setStdinEcho(original_echo);
        throw;
    }
}
