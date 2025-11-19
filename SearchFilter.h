#ifndef IRONVAULT_MANAGER_SEARCHFILTER_H
#define IRONVAULT_MANAGER_SEARCHFILTER_H

#include "CredentialRecord.h"
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

};


#endif //IRONVAULT_MANAGER_SEARCHFILTER_H
