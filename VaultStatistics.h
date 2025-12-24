#ifndef VAULTSTATISTICS_H
#define VAULTSTATISTICS_H

#include <vector>
#include <numeric>
#include <type_traits>
#include <cmath>

// Пространство имен для утилит
namespace VaultStats {

    // Ограничение: Тип T должен быть арифметическим (int, double, float)
    // Используем std::enable_if для SFINAE (Substitution Failure Is Not An Error)
    template<typename T>
    typename std::enable_if<std::is_arithmetic<T>::value, double>::type
    calculateAverage(const std::vector<T>& values) {
        if (values.empty()) {
            return 0.0;
        }

        // STL Algorithm: std::accumulate (сумма элементов)
        double sum = std::accumulate(values.begin(), values.end(), 0.0);
        return sum / values.size();
    }

    // Еще одна шаблонная функция для поиска медианы
    template<typename T>
    typename std::enable_if<std::is_arithmetic<T>::value, T>::type
    calculateMedian(std::vector<T> values) { // Принимаем по значению, чтобы сортировать копию
        if (values.empty()) return 0;

        size_t n = values.size();
        // STL Algorithm: std::nth_element (частичная сортировка, быстрее полной)
        std::nth_element(values.begin(), values.begin() + n/2, values.end());
        return values[n/2];
    }
}

#endif