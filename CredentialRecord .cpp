#include "CredentialRecord .h"
#include "sstream"
#include "iomanip"
#include "stdexcept"

//Конструктор
CredentialRecord::CredentialRecord()
        : service_name(""), url(""), login(""), encrypted_password(""),
          category("General"), internal_key(""), last_modified(std::time(nullptr)) {}


// Параметризованный конструктор
CredentialRecord::CredentialRecord(const std::string& service, const std::string& url,
                                   const std::string& login, const std::string& encrypted_password,
                                   const std::string& category)
        : service_name(service), url(url), login(login),
          encrypted_password(encrypted_password), category(category),
          internal_key(""), last_modified(std::time(nullptr)) {}
