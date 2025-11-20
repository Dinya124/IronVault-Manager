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
bool
SecureInputBuffer::readFromStdinWithCallback(const std::function<void(size_t, size_t)> &callback, bool hide_input) {
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
            } else if (c == BACKSPACE) {
                handleBackspace();
            } else if (c == CTRL_C || c == CTRL_D) {
                secureClear();
                setStdinEcho(original_echo);
                return false; // Прервано пользователем
            } else if (isValidCharacter(c)) {
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

    } catch (const std::exception &e) {
        setStdinEcho(original_echo);
        throw;
    }
}

// Очистка буфера
void SecureInputBuffer::clear() {
    std::fill(buffer.begin(), buffer.end(), 0);
    position = 0;
}

// Безопасная очистка (заполнение нулями)
void SecureInputBuffer::secureClear() {
    std::fill(buffer.begin(), buffer.end(), 0);
    position = 0;

    // Дополнительная гарантия очистки
    for (auto &c: buffer) {
        c = 0;
    }
}

// Изменение размера буфера
void SecureInputBuffer::resize(size_t new_size) {
    if (new_size > MAX_BUFFER_SIZE) {
        throw std::invalid_argument("New size exceeds maximum buffer size");
    }

    secureClear();
    buffer.resize(new_size);
    std::fill(buffer.begin(), buffer.end(), 0);
}

// Получение данных как строки
std::string SecureInputBuffer::getString() const {
    return std::string(buffer.data(), position);
}

// Получение буфера
std::vector<char> SecureInputBuffer::getBuffer() const {
    return std::vector<char>(buffer.begin(), buffer.begin() + position);
}

// Получение размера данных
size_t SecureInputBuffer::getSize() const {
    return position;
}

// Проверка на пустоту
bool SecureInputBuffer::isEmpty() const {
    return position == 0;
}

// Получение емкости буфера
size_t SecureInputBuffer::getCapacity() const {
    return buffer.size();
}

// Настройка отображения ввода
void SecureInputBuffer::setEchoEnabled(bool enabled) {
    echo_enabled = enabled;
}

void SecureInputBuffer::setMaskChar(char mask) {
    mask_char = mask;
}

bool SecureInputBuffer::isEchoEnabled() const {
    return echo_enabled;
}

char SecureInputBuffer::getMaskChar() const {
    return mask_char;
}

// Проверки безопасности
bool SecureInputBuffer::containsNullBytes() const {
    for (size_t i = 0; i < position; ++i) {
        if (buffer[i] == '\0') {
            return true;
        }
    }
    return false;
}

bool SecureInputBuffer::exceedsMaxSize() const {
    return position >= MAX_BUFFER_SIZE;
}

bool SecureInputBuffer::isValidUtf8() const {
    for (size_t i = 0; i < position; ++i) {
        if (static_cast<unsigned char>(buffer[i]) > 127) {
            return true; // Упрощенная проверка
        }
    }
    return true;
}

// Статические методы
std::string SecureInputBuffer::readSecureString(bool hide_input) {
    SecureInputBuffer buffer;
    if (buffer.readFromStdin(hide_input)) {
        return buffer.getString();
    }
    return "";
}

std::string SecureInputBuffer::readSecureStringWithSize(size_t max_size, bool hide_input) {
    SecureInputBuffer buffer(max_size);
    if (buffer.readFromStdin(hide_input)) {
        return buffer.getString();
    }
    return "";
}

void SecureInputBuffer::secureStringClear(std::string &str) {
    if (!str.empty()) {
        std::fill(str.begin(), str.end(), 0);
        str.clear();
    }
}

// Утилиты
void SecureInputBuffer::trim() {
    trimLeft();
    trimRight();
}

void SecureInputBuffer::trimLeft() {
    size_t start = 0;
    while (start < position && std::isspace(buffer[start])) {
        start++;
    }

    if (start > 0) {
        std::copy(buffer.begin() + start, buffer.begin() + position, buffer.begin());
        position -= start;
        std::fill(buffer.begin() + position, buffer.end(), 0);
    }
}

void SecureInputBuffer::trimRight() {
    while (position > 0 && std::isspace(buffer[position - 1])) {
        position--;
        buffer[position] = 0;
    }
}

// Приватные методы

void SecureInputBuffer::initializeBuffer() {
    buffer.resize(DEFAULT_BUFFER_SIZE);
    std::fill(buffer.begin(), buffer.end(), 0);
}

bool SecureInputBuffer::growBuffer() {
    if (buffer.size() >= MAX_BUFFER_SIZE) {
        return false;
    }

    size_t new_size = std::min(buffer.size() * 2, MAX_BUFFER_SIZE);
    buffer.resize(new_size);
    std::fill(buffer.begin() + position, buffer.end(), 0);
    return true;
}

void SecureInputBuffer::handleBackspace() {
    if (position > 0) {
        position--;
        buffer[position] = 0;

        if (echo_enabled) {
            std::cout << "\b \b" << std::flush;
        }
    }
}

void SecureInputBuffer::handleCharacter(char c, bool hide_input) {
    if (position >= buffer.size() - 1) {
        if (!growBuffer()) {
            throw std::runtime_error("Buffer full");
        }
    }

    buffer[position++] = c;
    buffer[position] = 0;

    if (echo_enabled) {
        if (hide_input) {
            std::cout << mask_char << std::flush;
        } else {
            std::cout << c << std::flush;
        }
    }
}

void SecureInputBuffer::displayMask(size_t current_size, bool hide_input) const {
    if (echo_enabled && hide_input) {
        std::cout << "\r";
        for (size_t i = 0; i < current_size; ++i) {
            std::cout << mask_char;
        }
        std::cout << std::flush;
    }
}