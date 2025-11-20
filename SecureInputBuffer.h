#ifndef IRONVAULT_MANAGER_SECUREINPUTBUFFER_H
#define IRONVAULT_MANAGER_SECUREINPUTBUFFER_H

#include <vector>
#include <string>
#include <functional>

class SecureInputBuffer {

private:
    std::vector<char> buffer;
    size_t position;
    bool echo_enabled;
    char mask_char;

    // Константы
    static const size_t DEFAULT_BUFFER_SIZE = 1024;
    static const size_t MAX_BUFFER_SIZE = 65536;
    static const char BACKSPACE = 127;
    static const char ENTER = 10;
    static const char CTRL_C = 3;
    static const char CTRL_D = 4;
public:
    // Конструкторы
    SecureInputBuffer();

    explicit SecureInputBuffer(size_t initial_size);

    // Основные методы ввода
    bool readFromStdin(bool hide_input = true);

    bool readFromStdinWithCallback(const std::function<void(size_t, size_t)> &callback, bool hide_input = true);

    // Методы очистки и управления
    void clear();

    void secureClear();

    void resize(size_t new_size);

    // Методы доступа к данным
    std::string getString() const;

    std::vector<char> getBuffer() const;

    size_t getSize() const;

    bool isEmpty() const;

    size_t getCapacity() const;

    // Настройки отображения
    void setEchoEnabled(bool enabled);

    void setMaskChar(char mask);

    bool isEchoEnabled() const;

    char getMaskChar() const;

    // Проверки безопасности
    bool containsNullBytes() const;

    bool exceedsMaxSize() const;

    bool isValidUtf8() const;

    // Статические методы для удобства
    static std::string readSecureString(bool hide_input = true);

    static std::string readSecureStringWithSize(size_t max_size, bool hide_input = true);

    static void secureStringClear(std::string &str);

    // Утилиты
    void trim();

    void trimLeft();

    void trimRight();
};


#endif //IRONVAULT_MANAGER_SECUREINPUTBUFFER_H
