#include "pid_manager.h"

extern "C" {
#include <globus_gridftp_server.h>
}

#include <curl/curl.h>
#include <curl/easy.h>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

struct string {
  char *ptr;
  size_t len;
};

void init_string(struct string *s) {
    s->len = 0;
    s->ptr = static_cast<char*>(malloc(s->len+1));
    if (s->ptr == NULL) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: manage_pid malloc() failed\n");
    }
    s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
    size_t new_len = s->len + size*nmemb;
    s->ptr = static_cast<char*>(realloc(s->ptr, new_len+1));
    if (s->ptr == NULL) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: manage_pid realloc() failed\n");
    }
    memcpy(s->ptr+s->len, ptr, size*nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size*nmemb;
}


int manage_pid(char *pid_handle_URL, char *PID,  char **URL) {
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: manage_pid invoked..\n");
    CURL *curl;
    CURLcode res;
    struct string s;
 
    curl = curl_easy_init();


    if(curl) {
        init_string(&s);
        char* completeURL;
        
        unsigned int len = strlen(pid_handle_URL);
        // Remove last "/" from handle URL
        if (pid_handle_URL && pid_handle_URL[len - 1] == '/') 
        {
            pid_handle_URL[len - 1] = 0;
        }

        completeURL = static_cast<char*>(malloc(strlen(pid_handle_URL)+strlen(PID)+1));
        strcpy(completeURL, pid_handle_URL);
        strcat(completeURL, PID);

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: complete handle URL: %s\n", completeURL);
        curl_easy_setopt(curl, CURLOPT_URL, completeURL);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
 
        // Perform the request, res will get the return code
        res = curl_easy_perform(curl);

        // Check for errors
        if(res != CURLE_OK)
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

            // always cleanup
            free(s.ptr);
            curl_easy_cleanup(curl);
            return res;
        }
        curl_easy_cleanup(curl);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: JSON output from the Handle Server: %s\n", s.ptr);

        try {
            const auto res_json = nlohmann::json::parse(s.ptr);
            std::printf("JSON output: %s..\n", s.ptr);
            auto responseCode = res_json.at("responseCode").get<nlohmann::json::number_integer_t>();
            if (1 != responseCode) {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: JSON responseCode =  %i\n", responseCode);
                free(s.ptr);
                return responseCode;
            }
            const auto &values = res_json.at("values");
            for (const auto& value : values) {
                const std::string& value_type = value.at("type").get_ref<const std::string&>();
                if (value_type == "URL") {
                    const std::string& myURL = value.at("data").at("value").get_ref<const std::string&>();
                    *URL = static_cast<char*>(std::calloc(myURL.size() + 1, sizeof(char)));
                    std::memcpy(*URL, myURL.c_str(), myURL.size());
                    (*URL)[myURL.size()] = '\0';
                    std::free(s.ptr);
                    return 0;
                }
            }
        }
        catch (const nlohmann::json::exception& e) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: JSON error in pid_manager: %s\n", e.what());
        }
        std::free(s.ptr);
        return 1;
    }
    return 1;
}
