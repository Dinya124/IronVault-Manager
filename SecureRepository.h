#ifndef SECUREREPOSITORY_H
#define SECUREREPOSITORY_H

#include <vector>
#include <map>
#include <memory>
#include <algorithm>
#include <stdexcept>
#include <type_traits>
#include "BaseRecord.h"

// Требование: Класс должен быть наследником BaseRecord
template <typename T>
class SecureRepository {
    // Проверка типа на этапе компиляции (Constraint)
    static_assert(std::is_base_of<BaseRecord, T>::value, "Template type T must inherit from BaseRecord");

private:
    // Контейнеры STL
    std::vector<std::shared_ptr<T>> storage; // Полиморфное хранение
    std::map<std::string, std::shared_ptr<T>> index_by_service; // Быстрый доступ (Map)

public:
    SecureRepository() = default;

    // Шаблонный метод: добавление записи
    void add(const T& item) {
        // Создаем копию через clone() и оборачиваем в smart pointer
        std::shared_ptr<T> newItem(static_cast<T*>(item.clone()));
        storage.push_back(newItem);

        // Пытаемся индексировать, если это CredentialRecord (через dynamic_cast или проверку)
        // Для упрощения индексируем просто по описанию
        index_by_service[newItem->getDescription()] = newItem;
    }

    // Шаблонный метод: добавление через указатель
    void addPtr(std::shared_ptr<T> item) {
        if (!item) return;
        storage.push_back(item);
    }

    // Не шаблонный метод: получить количество
    size_t count() const {
        return storage.size();
    }

    // Использование std::remove_if (Algorithm)
    bool removeByDescription(const std::string& desc) {
        auto initial_size = storage.size();

        // STL remove_if идиома (Erase-Remove)
        storage.erase(
                std::remove_if(storage.begin(), storage.end(),
                               [&desc](const std::shared_ptr<T>& ptr) {
                                   return ptr->getDescription() == desc; // Предполагается, что description хранит имя сервиса
                               }),
                storage.end()
        );

        // Чистим карту
        index_by_service.erase(desc);

        return storage.size() < initial_size;
    }

    // Метод для доступа к сырому вектору (для алгоритмов сортировки вовне)
    std::vector<std::shared_ptr<T>>& getStorage() {
        return storage;
    }

    const std::vector<std::shared_ptr<T>>& getStorage() const {
        return storage;
    }

    void clear() {
        storage.clear();
        index_by_service.clear();
    }
};

#endif