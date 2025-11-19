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

};


#endif //IRONVAULT_MANAGER_SEARCHFILTER_H
