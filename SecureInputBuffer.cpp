#include "SecureInputBuffer.h"
#include <iostream>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <vector>
#include <cctype>

// Системно-зависимые заголовки
#ifdef _WIN32
#include <windows.h>
#include <conio.h> // Для _getch()
#else
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#endif

// --------------------------------------------------------------------------
// ВНЕШНИЕ ОПРЕДЕЛЕНИЯ СТАТИЧЕСКИХ ЧЛЕНОВ (ИСПРАВЛЕНИЕ ОШИБКИ ЛИНКОВЩИКА)
// Эти переменные должны быть определены в одном .cpp файле,
// даже если они инициализированы в .h.
// --------------------------------------------------------------------------
const size_t SecureInputBuffer::DEFAULT_BUFFER_SIZE;
const size_t SecureInputBuffer::MAX_BUFFER_SIZE;
const char SecureInputBuffer::BACKSPACE;
const char SecureInputBuffer::ENTER;
const char SecureInputBuffer::CTRL_C;
const char SecureInputBuffer::CTRL_D;
// --------------------------------------------------------------------------

// Константы клавиш для кроссплатформенности
#ifdef _WIN32
static const int KEY_ENTER_CODE = 13;       // Windows Enter (\r)
static const int KEY_BACKSPACE_CODE = 8;    // Windows Backspace
#else
static const int KEY_ENTER_CODE = 10;       // Linux/Mac Enter (\n)
    static const int KEY_BACKSPACE_CODE = 127;  // Linux Backspace (часто 127)
#endif


// Конструктор по умолчанию
SecureInputBuffer::SecureInputBuffer()
        : position(0), echo_enabled(false), mask_char('*') {
    initializeBuffer();
}

// Конструктор с размером
SecureInputBuffer::SecureInputBuffer(size_t initial_size)
        : position(0), echo_enabled(false), mask_char('*') {
    if (initial_size == 0 || initial_size > MAX_BUFFER_SIZE) {
        throw std::invalid_argument("Invalid buffer size");
    }
    buffer.resize(initial_size);
    std::fill(buffer.begin(), buffer.end(), 0);
}

void SecureInputBuffer::initializeBuffer() {
    buffer.resize(DEFAULT_BUFFER_SIZE);
    std::fill(buffer.begin(), buffer.end(), 0);
}

// Основной метод чтения (обертка)
bool SecureInputBuffer::readFromStdin(bool hide_input) {
    return readFromStdinWithCallback(nullptr, hide_input);
}

// Основная логика чтения
bool SecureInputBuffer::readFromStdinWithCallback(const std::function<void(size_t, size_t)> &callback, bool hide_input) {
    clear(); // Очищаем буфер перед новым вводом

    // Установка небуферизованного режима. В Windows _getch делает это сам, но для
    // кроссплатформенности вызываем setStdinEcho
    bool original_echo_state = setStdinEcho(false);

    try {
        std::cout.flush();

        while (true) {
            int ch = getChar();

            // Обработка ENTER
            if (ch == KEY_ENTER_CODE || ch == ENTER) { // KEY_ENTER_CODE (13) для Windows, ENTER (10) для Linux
                std::cout << std::endl; // Переводим строку визуально
                break;
            }

            // Обработка Backspace
            if (ch == KEY_BACKSPACE_CODE || ch == BACKSPACE) {
                handleBackspace();
                if (callback) callback(position, buffer.size());
                continue;
            }

            // Обработка Ctrl+C / Ctrl+D
            if (ch == CTRL_C || ch == CTRL_D) {
                secureClear();
                setStdinEcho(original_echo_state);
                return false; // Отмена ввода
            }

            // Игнорируем спецсимволы и функциональные клавиши
            if (ch == 0 || ch == 0xE0) {
                if (getChar() != -1) continue; // Считываем второй код и игнорируем
            }

            // Обработка обычного символа
            char c = static_cast<char>(ch);
            if (isValidCharacter(c)) {
                handleCharacter(c, hide_input);
                if (callback) callback(position, buffer.size());
            }

            // Проверка переполнения
            if (exceedsMaxSize()) {
                secureClear();
                setStdinEcho(original_echo_state);
                throw std::runtime_error("Input exceeds maximum allowed size");
            }
        }

        setStdinEcho(original_echo_state);
        return true;

    } catch (...) {
        // Гарантируем восстановление режима терминала
        setStdinEcho(original_echo_state);
        throw;
    }
}

// Системно-зависимое получение символа
int SecureInputBuffer::getChar() {
#ifdef _WIN32
    return _getch(); // Conio.h: читает символ без ожидания Enter и без эха
#else
    return getchar(); // В Linux должен работать в небуферизованном режиме после setStdinEcho(false)
#endif
}

// Настройка терминала
bool SecureInputBuffer::setStdinEcho(bool enable) {
#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    if (!GetConsoleMode(hStdin, &mode)) return false;

    if (!enable) {
        mode &= ~ENABLE_ECHO_INPUT;
        mode &= ~ENABLE_LINE_INPUT; // Дополнительно отключаем буферизацию
    } else {
        mode |= ENABLE_ECHO_INPUT;
        mode |= ENABLE_LINE_INPUT;
    }
    return SetConsoleMode(hStdin, mode) != 0;
#else
    struct termios tty;
    if (tcgetattr(STDIN_FILENO, &tty) != 0) return false;

    if (!enable) {
        tty.c_lflag &= ~ECHO;
        tty.c_lflag &= ~ICANON; // Отключаем буферизацию
        tty.c_cc[VMIN] = 1;
        tty.c_cc[VTIME] = 0;
    } else {
        tty.c_lflag |= ECHO;
        tty.c_lflag |= ICANON;
    }
    return tcsetattr(STDIN_FILENO, TCSANOW, &tty) == 0;
#endif
}

// Обработка Backspace
void SecureInputBuffer::handleBackspace() {
    if (position > 0) {
        position--;
        buffer[position] = 0;

        // Визуальное удаление символа из консоли
        // \b - сдвиг назад, ' ' - стирание символа, \b - сдвиг назад снова
        std::cout << "\b \b" << std::flush;
    }
}

// Обработка обычного символа
void SecureInputBuffer::handleCharacter(char c, bool hide_input) {
    if (position >= buffer.size() - 1) {
        if (!growBuffer()) {
            throw std::runtime_error("Buffer full");
        }
    }

    buffer[position++] = c;
    buffer[position] = 0; // Null-terminate

    if (hide_input) {
        std::cout << mask_char << std::flush;
    } else {
        std::cout << c << std::flush;
    }
}

// Утилиты буфера
bool SecureInputBuffer::growBuffer() {
    if (buffer.size() >= MAX_BUFFER_SIZE) return false;
    size_t new_size = std::min(buffer.size() * 2, MAX_BUFFER_SIZE);
    buffer.resize(new_size);
    std::fill(buffer.begin() + position, buffer.end(), 0);
    return true;
}

void SecureInputBuffer::clear() {
    std::fill(buffer.begin(), buffer.end(), 0);
    position = 0;
}

void SecureInputBuffer::secureClear() {
    // Гарантированная перезапись памяти
    volatile char* p = buffer.data();
    for (size_t i = 0; i < buffer.capacity(); ++i) {
        p[i] = 0;
    }
    position = 0;
}

void SecureInputBuffer::resize(size_t new_size) {
    if (new_size > MAX_BUFFER_SIZE) throw std::invalid_argument("Size too large");
    secureClear();
    buffer.resize(new_size);
}

std::string SecureInputBuffer::getString() const {
    if (position == 0) return "";
    return std::string(buffer.data(), position);
}

std::vector<char> SecureInputBuffer::getBuffer() const {
    return std::vector<char>(buffer.begin(), buffer.begin() + position);
}

size_t SecureInputBuffer::getSize() const { return position; }
bool SecureInputBuffer::isEmpty() const { return position == 0; }
size_t SecureInputBuffer::getCapacity() const { return buffer.size(); }

void SecureInputBuffer::setEchoEnabled(bool enabled) { echo_enabled = enabled; }
void SecureInputBuffer::setMaskChar(char mask) { mask_char = mask; }
bool SecureInputBuffer::isEchoEnabled() const { return echo_enabled; }
char SecureInputBuffer::getMaskChar() const { return mask_char; }

bool SecureInputBuffer::isValidCharacter(char c) const {
    // Разрешаем печатные ASCII символы (от пробела до тильды) и расширенные (UTF-8)
    return (c >= 32 && c <= 126) || (static_cast<unsigned char>(c) >= 128);
}

bool SecureInputBuffer::containsNullBytes() const {
    for (size_t i = 0; i < position; ++i) {
        if (buffer[i] == 0) return true;
    }
    return false;
}

bool SecureInputBuffer::exceedsMaxSize() const {
    return position >= MAX_BUFFER_SIZE;
}

bool SecureInputBuffer::isValidUtf8() const {
    return true; // Упрощено
}

// Статические методы-обертки
std::string SecureInputBuffer::readSecureString(bool hide_input) {
    SecureInputBuffer buf;
    buf.setEchoEnabled(true);
    if (buf.readFromStdin(hide_input)) {
        std::string result = buf.getString();
        buf.secureClear();
        return result;
    }
    buf.secureClear();
    return "";
}

std::string SecureInputBuffer::readSecureStringWithSize(size_t max_size, bool hide_input) {
    SecureInputBuffer buf(max_size);
    buf.setEchoEnabled(true);
    if (buf.readFromStdin(hide_input)) {
        std::string result = buf.getString();
        buf.secureClear();
        return result;
    }
    buf.secureClear();
    return "";
}

void SecureInputBuffer::secureStringClear(std::string &str) {
    if (str.empty()) return;
    volatile char* p = &str[0];
    for (size_t i = 0; i < str.size(); ++i) {
        p[i] = 0;
    }
    str.clear();
}

// Методы обрезки пробелов
void SecureInputBuffer::trim() {
    trimLeft();
    trimRight();
}

void SecureInputBuffer::trimLeft() {
    size_t start = 0;
    while (start < position && std::isspace(static_cast<unsigned char>(buffer[start]))) {
        start++;
    }
    if (start > 0) {
        std::copy(buffer.begin() + start, buffer.begin() + position, buffer.begin());
        size_t new_pos = position - start;
        std::fill(buffer.begin() + new_pos, buffer.begin() + position, 0);
        position = new_pos;
    }
}

void SecureInputBuffer::trimRight() {
    while (position > 0 && std::isspace(static_cast<unsigned char>(buffer[position - 1]))) {
        position--;
        buffer[position] = 0;
    }
}