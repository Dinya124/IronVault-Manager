#include <string>
#include <vector>
#include <limits>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <filesystem>
#include <memory> // Для dynamic_pointer_cast и unique_ptr

// Подключение модулей проекта
#include "CredentialVault.h"
#include "BaseRecord.h"
#include "CredentialRecord.h"
#include "SecureInputBuffer.h"
#include "SearchFilter.h"
#include "DataEncryption.h" // Для шифрования при добавлении

// --- Вспомогательные функции ---

void clearInputBuffer() {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void pauseConsole() {
    std::cout << "\nНажмите Enter, чтобы продолжить...";
    if (std::cin.peek() == '\n') std::cin.ignore();
    std::cin.get();
}

// Помощник для обрезки длинных строк
std::string truncate(std::string str, size_t width) {
    if (str.length() > width) {
        return str.substr(0, width - 3) + "...";
    }
    return str;
}

void printHeader(const std::string& userProfile) {

    std::cout << "========================================\n";
    std::cout << "      IRON VAULT PASSWORD MANAGER       \n";
    std::cout << "========================================\n";
    if (!userProfile.empty()) {
        std::cout << "Пользователь: [" << userProfile << "]\n";
    }
    std::cout << "========================================\n";
}

// --- Функции отображения (Полиморфные) ---

void viewRecordDetails(const BaseRecord& record, const std::string& masterPassword) {
    std::cout << "\n--- Подробности записи ---\n";
    // Полиморфный вызов: каждый тип записи сам знает, как себя показать
    std::cout << record.getDetailedInfo(masterPassword) << "\n";
    std::cout << "--------------------------\n";
}

// Функция вывода таблицы. Принимает список указателей на базовый класс.
void printRecordList(const std::vector<const BaseRecord*>& records) {
    if (records.empty()) {
        std::cout << "Список пуст.\n";
        return;
    }

    // Ширина колонок
    const int wNo = 4;
    const int wServ = 22;
    const int wLog = 22;
    const int wCat = 15;

    // Шапка
    std::cout << " " << std::string(wNo + wServ + wLog + wCat + 10, '-') << "\n";
    std::cout << " | " << std::left << std::setw(wNo) << "No"
              << " | " << std::setw(wServ) << "Сервис/Тип"
              << " | " << std::setw(wLog) << "Логин/Инфо"
              << " | " << std::setw(wCat) << "Категория" << " |\n";
    std::cout << " " << std::string(wNo + wServ + wLog + wCat + 10, '-') << "\n";

    // Вывод строк
    for (size_t i = 0; i < records.size(); ++i) {
        const BaseRecord* ptr = records[i];

        std::string sName, sLog, sCat;

        // Пытаемся привести к CredentialRecord, чтобы достать специфичные поля
        if (auto* cred = dynamic_cast<const CredentialRecord*>(ptr)) {
            sName = cred->getServiceName();
            sLog = cred->getLogin();
            sCat = cred->getCategory();
        } else {
            // Если добавим другие типы записей (например, заметки), будет работать этот блок
            sName = ptr->getType();
            sLog = ptr->getSummary();
            sCat = "-";
        }

        std::cout << " | " << std::left << std::setw(wNo) << (i + 1)
                  << " | " << std::setw(wServ) << truncate(sName, wServ)
                  << " | " << std::setw(wLog) << truncate(sLog, wLog)
                  << " | " << std::setw(wCat) << truncate(sCat, wCat) << " |\n";
    }
    std::cout << " " << std::string(wNo + wServ + wLog + wCat + 10, '-') << "\n";
}

// --- Обработка команд ---

// Добавление записи (обновлено для unique_ptr)
void handleAddRecord(CredentialVault& vault, const std::string& masterPassword) {
    std::string service, login, url, category, password;
    if (std::cin.peek() != '\n') clearInputBuffer(); else std::cin.ignore();

    std::cout << "\n--- Новая запись ---\n";
    try {
        std::cout << "Сервис (обязательно): "; std::getline(std::cin, service);
        if (service.empty()) throw std::runtime_error("Имя сервиса не может быть пустым");

        // Проверка уникальности
        if (!vault.isServiceNameUnique(service)) throw std::runtime_error("Запись с таким сервисом уже существует");

        std::cout << "URL: "; std::getline(std::cin, url);
        std::cout << "Логин: "; std::getline(std::cin, login);
        std::cout << "Категория (по умолчанию General): "; std::getline(std::cin, category);

        std::cout << "Сгенерировать пароль? (y/n): ";
        char ch;
        if (!(std::cin >> ch)) { std::cin.clear(); ch = 'n'; }
        clearInputBuffer();

        if (ch == 'y' || ch == 'Y') {
            password = vault.generatePassword(16, true, true, true, true);
            std::cout << "Сгенерирован пароль: " << password << "\n";
        } else {
            std::cout << "Введите пароль: ";
            password = SecureInputBuffer::readSecureString();
            std::cout << "\n";
        }

        std::string encPass = DataEncryption::encrypt(password, masterPassword);

        // Создаем объект через unique_ptr (Полиморфизм)
        auto newRecord = std::make_unique<CredentialRecord>(service, url, login, encPass, category);

        // Перемещаем (move) владение объектом в хранилище
        if (vault.addRecord(std::move(newRecord))) {
            std::cout << "Успешно добавлено!\n";
        } else {
            std::cout << "Ошибка добавления.\n";
        }

    } catch (const std::exception& e) {
        std::cout << "\n[ОШИБКА]: " << e.what() << "\n";
    }
}

// Просмотр всех записей с выбором
void handleShowAllRecords(CredentialVault& vault, const std::string& masterPassword) {
    // Получаем вектор указателей (const BaseRecord*)
    auto records = vault.getAllRecords();

    if (records.empty()) {
        std::cout << "\nХранилище пусто.\n";
        return;
    }

    // Показываем список
    printRecordList(records);

    // Цикл выбора
    while (true) {
        std::cout << "\nВведите номер записи для просмотра (0 - назад): ";
        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear(); clearInputBuffer();
            std::cout << "Неверный ввод.\n";
            continue;
        }
        clearInputBuffer();

        if (choice == 0) break;

        if (choice > 0 && choice <= (int)records.size()) {
            // Выбираем указатель из списка
            const BaseRecord* selected = records[choice - 1];

            // Полиморфный просмотр деталей
            viewRecordDetails(*selected, masterPassword);
            pauseConsole();

            // Перерисовываем список, чтобы пользователю было удобно
            printHeader("ПРОСМОТР");
            printRecordList(records);
        } else {
            std::cout << "Неверный номер записи.\n";
        }
    }
}

// Расширенный поиск
void handleAdvancedSearch(CredentialVault& vault, const std::string& masterPassword) {
    SearchFilter filter;
    bool searching = true;

    while (searching) {
        printHeader("ПОИСК");
        std::cout << "Текущие фильтры:\n";
        std::cout << "1. Сервис:    " << (filter.getServiceNameQuery().empty() ? "[Любой]" : filter.getServiceNameQuery()) << "\n";
        std::cout << "2. Логин:     " << (filter.getLoginQuery().empty() ? "[Любой]" : filter.getLoginQuery()) << "\n";
        std::cout << "3. Категория: " << (filter.getCategoryQuery().empty() ? "[Любая]" : filter.getCategoryQuery()) << "\n";
        std::cout << "-----------------------\n";
        std::cout << "4. ВЫПОЛНИТЬ ПОИСК\n";
        std::cout << "5. Сбросить фильтры\n";
        std::cout << "0. Назад в меню\n";
        std::cout << "Ваш выбор: ";

        int choice;
        if (!(std::cin >> choice)) { std::cin.clear(); clearInputBuffer(); continue; }
        clearInputBuffer();

        std::string input;
        switch (choice) {
            case 1:
                std::cout << "Введите часть названия сервиса: ";
                std::getline(std::cin, input);
                filter.setServiceNameQuery(input);
                break;
            case 2:
                std::cout << "Введите логин для поиска: ";
                std::getline(std::cin, input);
                filter.setLoginQuery(input);
                break;
            case 3:
                std::cout << "Введите категорию: ";
                std::getline(std::cin, input);
                filter.setCategoryQuery(input);
                break;
            case 4: {
                // Выполнение поиска (возвращает vector<const BaseRecord*>)
                auto results = vault.searchRecords(filter);

                std::cout << "\n--- Результаты поиска (" << results.size() << ") ---\n";
                printRecordList(results);

                if (!results.empty()) {
                    std::cout << "\nВведите номер записи для просмотра (0 - новый поиск): ";
                    int idx;
                    if (std::cin >> idx && idx > 0 && idx <= (int)results.size()) {
                        clearInputBuffer();
                        viewRecordDetails(*results[idx - 1], masterPassword);
                        pauseConsole();
                    } else {
                        clearInputBuffer();
                    }
                } else {
                    pauseConsole();
                }
                break;
            }
            case 5:
                filter.clear();
                std::cout << "Фильтры сброшены.\n";
                break;
            case 0:
                searching = false;
                break;
            default:
                break;
        }
    }
}

// --- УПРАВЛЕНИЕ ПРОФИЛЯМИ ---

std::string getProfileFilename(const std::string& username) {
    return "vault_" + username + ".dat";
}

bool profileLogin(std::string& currentMasterPassword, std::string& currentUser, CredentialVault& vault) {
    std::string username;
    std::cout << "\nВведите имя пользователя (профиль): ";
    std::cin >> username;
    clearInputBuffer();

    if (username.empty()) return false;

    std::string filename = getProfileFilename(username);

    // Пересоздаем объект vault с новым файлом
    // Так как vault передается по ссылке из main, мы используем оператор присваивания (move assignment)
    // или создаем новый объект на месте.
    vault = CredentialVault(filename);

    bool isNewProfile = !std::filesystem::exists(filename);

    if (isNewProfile) {
        std::cout << "Профиль '" << username << "' не найден. Создать новый? (y/n): ";
        char c;
        if (!(std::cin >> c) || (c != 'y' && c != 'Y')) {
            clearInputBuffer();
            return false;
        }
        clearInputBuffer();

        std::cout << "Установите Мастер-пароль для нового профиля: ";
        std::string p1 = SecureInputBuffer::readSecureString();
        std::cout << "\nПовторите пароль: ";
        std::string p2 = SecureInputBuffer::readSecureString();
        std::cout << "\n";

        if (p1 != p2) {
            std::cout << "Пароли не совпадают!\n";
            return false;
        }
        if (p1.empty()) {
            std::cout << "Пароль не может быть пустым.\n";
            return false;
        }

        if (vault.loadFromFile(p1)) {
            currentMasterPassword = p1;
            currentUser = username;
            std::cout << "Профиль успешно создан!\n";
            vault.saveToFile(currentMasterPassword);
            return true;
        }
    } else {
        std::cout << "Введите Мастер-пароль для " << username << ": ";
        std::string pwd = SecureInputBuffer::readSecureString();
        std::cout << "\n";

        if (vault.loadFromFile(pwd)) {
            currentMasterPassword = pwd;
            currentUser = username;
            std::cout << "Вход выполнен успешно.\n";
            return true;
        } else {
            std::cout << "Неверный пароль или ошибка чтения файла.\n";
        }
    }
    return false;
}

// --- MAIN ---

int main() {
    // Настройка консоли для корректного вывода (UTF-8)
#ifdef _WIN32
    system("chcp 65001 > nul");
#endif

    // Глобальный цикл приложения
    while (true) {
        CredentialVault vault; // Объект хранилища
        std::string masterPassword;
        std::string currentUser;
        bool authenticated = false;

        printHeader("");
        std::cout << "Добро пожаловать в Iron Vault (Poly Edition).\n";

        // Цикл аутентификации
        while (!authenticated) {
            if (profileLogin(masterPassword, currentUser, vault)) {
                authenticated = true;
            } else {
                std::cout << "Повторить вход? (y/n/q-выход): ";
                char c;
                if (!(std::cin >> c)) c = 'q';
                clearInputBuffer();
                if (c == 'q' || c == 'Q') return 0;
            }
        }

        // Цикл сессии пользователя
        bool sessionActive = true;
        while (sessionActive) {
            printHeader(currentUser);
            // Используем std::endl для надежного вывода кириллицы
            std::cout << "1. Добавить запись" << std::endl;
            std::cout << "2. Поиск и просмотр (Расширенный)" << std::endl;
            std::cout << "3. Показать все записи" << std::endl;
            std::cout << "4. Категории" << std::endl;
            std::cout << "5. Генератор паролей" << std::endl;
            std::cout << "6. Сохранить изменения" << std::endl;
            std::cout << "7. Сменить пользователя" << std::endl;
            std::cout << "0. Выйти из программы" << std::endl;
            std::cout << "Выбор: ";

            int choice;
            if (!(std::cin >> choice)) {
                std::cin.clear(); clearInputBuffer();
                continue;
            }

            switch (choice) {
                case 1:
                    handleAddRecord(vault, masterPassword);
                    pauseConsole();
                    break;
                case 2:
                    handleAdvancedSearch(vault, masterPassword);
                    break;
                case 3:
                    handleShowAllRecords(vault, masterPassword);
                    break;
                case 4: {
                    auto cats = vault.getAllCategories();
                    std::cout << "\n--- Категории ---\n";
                    for (const auto& c : cats) std::cout << "- " << c << "\n";
                    pauseConsole();
                    break;
                }
                case 5:
                    std::cout << "\nПароль: " << vault.generatePassword(16, true, true, true, true) << "\n";
                    pauseConsole();
                    break;
                case 6:
                    if (vault.saveToFile(masterPassword)) std::cout << "Хранилище сохранено.\n";
                    else std::cout << "Ошибка сохранения!\n";
                    pauseConsole();
                    break;
                case 7:
                    vault.saveToFile(masterPassword); // Автосохранение
                    sessionActive = false; // Возврат к экрану логина
                    break;
                case 0:
                    vault.saveToFile(masterPassword); // Автосохранение
                    return 0; // Полный выход
                default:
                    std::cout << "Неверный выбор.\n";
                    pauseConsole();
                    break;
            }
        }
    }
    return 0;
}