#ifndef IRONVAULT_COMPILETIMEFEATURES_H
#define IRONVAULT_COMPILETIMEFEATURES_H

#include <cstdint>
#include <array>
#include <stdexcept>

// =========================================================
// ЗАДАНИЕ 1: Функция вне класса (consteval)
// Тема: Хеширование строк (FNV-1a) для проверки заголовков
// =========================================================

// Функция должна быть вычислена ИСКЛЮЧИТЕЛЬНО на этапе компиляции.
// В runtime вызова этой функции не останется, будет подставлена константа.
consteval uint64_t compileTimeHash(const char* str) {
    uint64_t hash = 14695981039346656037ull; // FNV offset basis
    while (*str) {
        hash ^= static_cast<uint64_t>(*str++);
        hash *= 1099511628211ull; // FNV prime
    }
    return hash;
}

// =========================================================
// ЗАДАНИЕ 2: Класс со статической инициализацией (constexpr ctor)
// Тема: Конфигурация криптографических параметров
// =========================================================

class CryptoConfig {
public:
    int aes_key_size;
    int block_size;
    int buffer_safety_margin;
    int max_password_length;

    // Конструктор должен быть constexpr, чтобы участвовать в constinit
    constexpr CryptoConfig(int security_level)
            : aes_key_size(0), block_size(16), buffer_safety_margin(0), max_password_length(0)
    {
        // Вычисляемые выражения в конструкторе
        if (security_level == 1) { // Standard
            aes_key_size = 128;
            max_password_length = 64;
        } else { // High (Paranoid)
            aes_key_size = 256;
            max_password_length = 128;
        }

        // Вычисляем безопасный размер буфера:
        // (Max pass + IV + Salt + Padding alignment) * 2 (safety factor)
        buffer_safety_margin = (max_password_length + block_size + 32) * 2;

        // Выравнивание по границе памяти (простая математика на этапе компиляции)
        if (buffer_safety_margin % 8 != 0) {
            buffer_safety_margin += (8 - (buffer_safety_margin % 8));
        }
    }

    // Метод, вычисляемый на этапе компиляции
    [[nodiscard]] constexpr int getOptimalBufferSize() const {
        return buffer_safety_margin + 1024; // Base overhead
    }
};

// =========================================================
// ЗАДАНИЕ 3: constinit переменная
// =========================================================

// constinit гарантирует, что эта переменная будет инициализирована
// до выполнения какого-либо кода в runtime.
// Сама переменная НЕ const, мы можем изменить настройки позже,
// но начальное состояние вычислено компилятором.
constinit static CryptoConfig globalCryptoConfig = CryptoConfig(2); // Level 2 = High Security

#endif //IRONVAULT_COMPILETIMEFEATURES_H