#ifndef IRONVAULT_MANAGER_SEARCHFILTER_H
#define IRONVAULT_MANAGER_SEARCHFILTER_H

#include "CredentialRecord .h"
#include <string>
#include <vector>
#include <memory>
#include <ctime>

class SearchFilter {
private:
    std::string service_name_query;
    std::string login_query;
    std::string url_query;
    std::string category_query;
    std::string notes_query;

    bool case_sensitive;
    bool exact_match;
    bool search_in_notes;

    std::time_t date_from;
    std::time_t date_to;

    std::vector<std::string> categories;
    std::vector<std::string> excluded_categories;
public:
    // Конструкторы
    SearchFilter();

    // Основной метод проверки соответствия
    bool matches(const CredentialRecord &record) const;

    // Сеттеры для критериев поиска
    void setServiceNameQuery(const std::string &query);

    void setLoginQuery(const std::string &query);

    void setUrlQuery(const std::string &query);

    void setCategoryQuery(const std::string &query);

    void setNotesQuery(const std::string &query);

    // Сеттеры для параметров поиска
    void setCaseSensitive(bool sensitive);

    void setExactMatch(bool exact);

    void setSearchInNotes(bool search_notes);

    // Сеттеры для временного диапазона
    void setDateRange(std::time_t from, std::time_t to);

    void setDateFrom(std::time_t from);

    void setDateTo(std::time_t to);

    // Сеттеры для категорий
    void setCategories(const std::vector<std::string> &categories_list);

    void setExcludedCategories(const std::vector<std::string> &excluded_list);

    void addCategory(const std::string &category);

    void addExcludedCategory(const std::string &category);

    // Очистка критериев
    void clear();

    void clearServiceNameQuery();

    void clearLoginQuery();

    void clearUrlQuery();

    void clearCategoryQuery();

    void clearNotesQuery();

    void clearDateRange();

    void clearCategories();

    void clearExcludedCategories();

    // Геттеры
    std::string getServiceNameQuery() const;

    std::string getLoginQuery() const;

    std::string getUrlQuery() const;

    std::string getCategoryQuery() const;

    std::string getNotesQuery() const;

    bool isCaseSensitive() const;

    bool isExactMatch() const;

    bool isSearchInNotes() const;

    std::time_t getDateFrom() const;

    std::time_t getDateTo() const;

    std::vector<std::string> getCategories() const;

    std::vector<std::string> getExcludedCategories() const;

    // Проверка активности фильтров
    bool isActive() const;

    bool hasTextFilters() const;

    bool hasDateFilters() const;

    bool hasCategoryFilters() const;

    // Статические методы для удобства
    static SearchFilter createServiceFilter(const std::string &service_name);

    static SearchFilter createCategoryFilter(const std::string &category);

    static SearchFilter createDateRangeFilter(std::time_t from, std::time_t to);

    static SearchFilter createTextSearchFilter(const std::string &text);

private:
    // Внутренние методы для проверки соответствия
    bool matchesServiceName(const CredentialRecord &record) const;

    bool matchesLogin(const CredentialRecord &record) const;

    bool matchesUrl(const CredentialRecord &record) const;

    bool matchesCategory(const CredentialRecord &record) const;

    bool matchesNotes(const CredentialRecord &record) const;

    bool matchesDateRange(const CredentialRecord &record) const;

    bool matchesCategories(const CredentialRecord &record) const;

    // Вспомогательные методы для работы со строками
    std::string toLower(const std::string &str) const;

    bool containsText(const std::string &text, const std::string &query) const;

    bool matchesText(const std::string &text, const std::string &query) const;

    // Вспомогательные методы для работы с категориями
    bool isInCategories(const std::string &category) const;

    bool isExcludedCategory(const std::string &category) const;
};




#endif //IRONVAULT_MANAGER_SEARCHFILTER_H
