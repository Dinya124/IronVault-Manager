#include "SearchFilter.h"
#include <algorithm>
#include <cctype>
#include <ctime>

SearchFilter::SearchFilter()
        : service_name_query(""), login_query(""), url_query(""), category_query(""), notes_query(""),
          case_sensitive(false), exact_match(false), search_in_notes(false),
          date_from(0), date_to(0) {}

// РЕАЛИЗАЦИЯ ПЕРЕГРУЗКИ ОПЕРАТОРА +
SearchFilter SearchFilter::operator+(const SearchFilter& other) const {
    SearchFilter result = *this;

    // Простая логика объединения: если в текущем фильтре поле пустое, берем из второго
    if (result.service_name_query.empty()) result.service_name_query = other.service_name_query;
    if (result.login_query.empty()) result.login_query = other.login_query;
    if (result.url_query.empty()) result.url_query = other.url_query;
    if (result.category_query.empty()) result.category_query = other.category_query;

    // Объединяем списки категорий
    result.categories.insert(result.categories.end(), other.categories.begin(), other.categories.end());

    // Удаляем дубликаты в категориях
    std::sort(result.categories.begin(), result.categories.end());
    result.categories.erase(std::unique(result.categories.begin(), result.categories.end()), result.categories.end());

    return result;
}

bool SearchFilter::matches(const CredentialRecord &record) const {
    if (!isActive()) return true;
    if (!matchesServiceName(record)) return false;
    if (!matchesLogin(record)) return false;
    if (!matchesUrl(record)) return false;
    if (!matchesCategory(record)) return false;
    if (!matchesNotes(record)) return false;
    if (!matchesDateRange(record)) return false;
    if (!matchesCategories(record)) return false;
    return true;
}

bool SearchFilter::matchesServiceName(const CredentialRecord &record) const {
    if (service_name_query.empty()) return true;
    return matchesText(record.getServiceName(), service_name_query);
}

bool SearchFilter::matchesLogin(const CredentialRecord &record) const {
    if (login_query.empty()) return true;
    return matchesText(record.getLogin(), login_query);
}

bool SearchFilter::matchesUrl(const CredentialRecord &record) const {
    if (url_query.empty()) return true;
    return matchesText(record.getUrl(), url_query);
}

bool SearchFilter::matchesCategory(const CredentialRecord &record) const {
    if (category_query.empty()) return true;
    return matchesText(record.getCategory(), category_query);
}

bool SearchFilter::matchesNotes(const CredentialRecord &record) const {
    if (notes_query.empty() || !search_in_notes) return true;
    return false; // Заглушка, так как поле Notes в Record пока нет
}

bool SearchFilter::matchesDateRange(const CredentialRecord &record) const {
    if (date_from == 0 && date_to == 0) return true;
    std::time_t record_time = record.getLastModified();
    if (date_from > 0 && record_time < date_from) return false;
    if (date_to > 0 && record_time > date_to) return false;
    return true;
}

bool SearchFilter::matchesCategories(const CredentialRecord &record) const {
    std::string category = record.getCategory();
    if (!categories.empty() && !isInCategories(category)) return false;
    if (!excluded_categories.empty() && isExcludedCategory(category)) return false;
    return true;
}

// Сеттеры
void SearchFilter::setServiceNameQuery(const std::string &query) { service_name_query = query; }
void SearchFilter::setLoginQuery(const std::string &query) { login_query = query; }
void SearchFilter::setUrlQuery(const std::string &query) { url_query = query; }
void SearchFilter::setCategoryQuery(const std::string &query) { category_query = query; }
void SearchFilter::setNotesQuery(const std::string &query) { notes_query = query; }
void SearchFilter::setDateRange(std::time_t from, std::time_t to) { date_from = from; date_to = to; }
void SearchFilter::setDateFrom(std::time_t from) { date_from = from; }
void SearchFilter::setDateTo(std::time_t to) { date_to = to; }
void SearchFilter::setCategories(const std::vector<std::string> &categories_list) { categories = categories_list; }
void SearchFilter::setExcludedCategories(const std::vector<std::string> &excluded_list) { excluded_categories = excluded_list; }
void SearchFilter::addCategory(const std::string &category) { if (!category.empty()) categories.push_back(category); }
void SearchFilter::addExcludedCategory(const std::string &category) { if (!category.empty()) excluded_categories.push_back(category); }
void SearchFilter::setSearchInNotes(bool search_notes) { search_in_notes = search_notes; }
void SearchFilter::setCaseSensitive(bool sensitive) { case_sensitive = sensitive; }
void SearchFilter::setExactMatch(bool exact) { exact_match = exact; }

// Очистка
void SearchFilter::clear() {
    service_name_query.clear(); login_query.clear(); url_query.clear(); category_query.clear(); notes_query.clear();
    case_sensitive = false; exact_match = false; search_in_notes = false;
    date_from = 0; date_to = 0;
    categories.clear(); excluded_categories.clear();
}
void SearchFilter::clearServiceNameQuery() { service_name_query.clear(); }
void SearchFilter::clearLoginQuery() { login_query.clear(); }
void SearchFilter::clearUrlQuery() { url_query.clear(); }
void SearchFilter::clearCategoryQuery() { category_query.clear(); }
void SearchFilter::clearNotesQuery() { notes_query.clear(); }
void SearchFilter::clearDateRange() { date_from = 0; date_to = 0; }
void SearchFilter::clearCategories() { categories.clear(); }
void SearchFilter::clearExcludedCategories() { excluded_categories.clear(); }

// Геттеры
std::string SearchFilter::getServiceNameQuery() const { return service_name_query; }
std::string SearchFilter::getLoginQuery() const { return login_query; }
std::string SearchFilter::getUrlQuery() const { return url_query; }
std::string SearchFilter::getCategoryQuery() const { return category_query; }
std::string SearchFilter::getNotesQuery() const { return notes_query; }
bool SearchFilter::isCaseSensitive() const { return case_sensitive; }
bool SearchFilter::isExactMatch() const { return exact_match; }
bool SearchFilter::isSearchInNotes() const { return search_in_notes; }
std::time_t SearchFilter::getDateFrom() const { return date_from; }
std::time_t SearchFilter::getDateTo() const { return date_to; }
std::vector<std::string> SearchFilter::getCategories() const { return categories; }
std::vector<std::string> SearchFilter::getExcludedCategories() const { return excluded_categories; }

bool SearchFilter::isActive() const {
    return hasTextFilters() || hasDateFilters() || hasCategoryFilters();
}
bool SearchFilter::hasTextFilters() const {
    return !service_name_query.empty() || !login_query.empty() || !url_query.empty() || !category_query.empty() || (!notes_query.empty() && search_in_notes);
}
bool SearchFilter::hasDateFilters() const { return date_from > 0 || date_to > 0; }
bool SearchFilter::hasCategoryFilters() const { return !categories.empty() || !excluded_categories.empty(); }

// Статические методы
SearchFilter SearchFilter::createServiceFilter(const std::string &service_name) {
    SearchFilter filter; filter.setServiceNameQuery(service_name); return filter;
}
SearchFilter SearchFilter::createCategoryFilter(const std::string &category) {
    SearchFilter filter; filter.setCategoryQuery(category); return filter;
}
SearchFilter SearchFilter::createDateRangeFilter(std::time_t from, std::time_t to) {
    SearchFilter filter; filter.setDateRange(from, to); return filter;
}
SearchFilter SearchFilter::createTextSearchFilter(const std::string &text) {
    SearchFilter filter;
    filter.setServiceNameQuery(text); filter.setLoginQuery(text); filter.setUrlQuery(text); filter.setCategoryQuery(text);
    filter.setSearchInNotes(true); filter.setNotesQuery(text);
    return filter;
}

// Вспомогательные
std::string SearchFilter::toLower(const std::string &str) const {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

bool SearchFilter::containsText(const std::string &text, const std::string &query) const {
    if (case_sensitive) return text.find(query) != std::string::npos;
    std::string text_lower = toLower(text);
    std::string query_lower = toLower(query);
    return text_lower.find(query_lower) != std::string::npos;
}

bool SearchFilter::matchesText(const std::string &text, const std::string &query) const {
    if (exact_match) {
        if (case_sensitive) return text == query;
        else return toLower(text) == toLower(query);
    }
    return containsText(text, query);
}

bool SearchFilter::isInCategories(const std::string &category) const {
    if (case_sensitive) return std::find(categories.begin(), categories.end(), category) != categories.end();
    std::string category_lower = toLower(category);
    for (const auto &cat: categories) if (toLower(cat) == category_lower) return true;
    return false;
}

bool SearchFilter::isExcludedCategory(const std::string &category) const {
    if (case_sensitive) return std::find(excluded_categories.begin(), excluded_categories.end(), category) != excluded_categories.end();
    std::string category_lower = toLower(category);
    for (const auto &cat: excluded_categories) if (toLower(cat) == category_lower) return true;
    return false;
}