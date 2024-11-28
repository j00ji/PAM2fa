#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <time.h>
#include <curl/curl.h>
#include <syslog.h>
#include <unistd.h>
#include <libconfig.h>
#include <grp.h>
#include <pwd.h>

#define TELEGRAM_URL "https://api.telegram.org/bot%s/sendMessage"
#define MAX_TOKEN_LENGTH 32
#define MAX_TELEGRAM_BOTKEY_LEN 128
#define MAX_TELEGRAM_ID_LEN 128

#define LOG_FILE "/tmp/pam_telegram_debug.log"

void log_message(const char *message) {
    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "%s\n", message);
        fclose(log);
    }
}

size_t fake_curl_write(void *p, size_t s, size_t nmemb, void *d) {
    (void)p;
    (void)d;
    return s * nmemb;
}

void generate_token(char *token, size_t length) {
    srand(time(NULL));
    for (size_t i = 0; i < length - 1; ++i) {
        token[i] = 'A' + (rand() % 26);
    }
    token[length - 1] = '\0';
}

int read_credentials(const char *username, char *chatid, char *botkey) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "/home/%s/.pam_telegram_2fa/credentials", username);

    FILE *file = fopen(filepath, "r");
    if (!file) {
        log_message("Failed to open credentials file.");
        return -1;
    }

    char line[128];
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "id=", 3) == 0) {
            strncpy(chatid, line + 3, MAX_TELEGRAM_ID_LEN);
            chatid[strcspn(chatid, "\n")] = 0; // Remove newline
        } else if (strncmp(line, "botkey=", 7) == 0) {
            strncpy(botkey, line + 7, MAX_TELEGRAM_BOTKEY_LEN);
            botkey[strcspn(botkey, "\n")] = 0; // Remove newline
        }
    }

    fclose(file);

    if (strlen(chatid) == 0 || strlen(botkey) == 0) {
        log_message("Invalid credentials file.");
        return -1;
    }

    return 0;
}

int user_in_group(const char *username, const char *groupname) {
    struct group *grp = getgrnam(groupname);
    if (!grp) {
        log_message("Group not found.");
        return 0;
    }

    struct passwd *pwd = getpwnam(username);
    if (!pwd) {
        log_message("User not found.");
        return 0;
    }

    // Check if the user is in the group
    char **members = grp->gr_mem;
    while (*members) {
        if (strcmp(*members, username) == 0) {
            return 1;
        }
        members++;
    }

    // Fallback: Check the user's primary group
    if (pwd->pw_gid == grp->gr_gid) {
        return 1;
    }

    return 0;
}

int send_auth_link(char *chatid, char *botkey, char *token) {
    CURL *curl;
    CURLcode response;
    char link[128];
    char url[512];
    char post[512];

    snprintf(link, sizeof(link), "http://127.0.0.1:8080/auth/%s", token);
    snprintf(url, sizeof(url), TELEGRAM_URL, botkey);
    snprintf(post, sizeof(post), "chat_id=%s&text=<a href=\"%s\">Click here to authenticate</a>&parse_mode=HTML", chatid, link);

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fake_curl_write);

        response = curl_easy_perform(curl);

        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    if (response != CURLE_OK) {
        log_message("CURL request failed.");
        return -1;
    }

    log_message("CURL request succeeded.");
    return 0;
}

int validate_token(char *token) {
    CURL *curl;
    CURLcode response;
    long http_code = 0;
    char status_url[128];

    snprintf(status_url, sizeof(status_url), "http://localhost:8080/auth/%s/status", token);

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, status_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fake_curl_write);

        response = curl_easy_perform(curl);

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    if (response != CURLE_OK) {
        log_message("CURL request failed.");
        return -1;
    }

    if (http_code == 200) {
        log_message("Token validated successfully.");
        return 0;
    } else {
        log_message("Token validation failed.");
        return -1;
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username = NULL;
    char botkey[MAX_TELEGRAM_BOTKEY_LEN] = {0};
    char chatid[MAX_TELEGRAM_ID_LEN] = {0};
    char token[MAX_TOKEN_LENGTH] = {0};
    int rval;

    // Get the username
    rval = pam_get_user(pamh, &username, "Username: ");
    if (rval != PAM_SUCCESS || !username) {
        log_message("Failed to retrieve username.");
        return rval;
    }

    if (strcmp("root", username) == 0) {
        return PAM_SUCCESS; // Skip authentication for root
    }

    // Check if the user belongs to the 2FA group
    if (!user_in_group(username, "2fa")) {
        log_message("User not in 2FA group. Skipping 2FA.");
        return PAM_SUCCESS;
    }

    // Load credentials from the user's credentials file
    if (read_credentials(username, chatid, botkey) != 0) {
        log_message("Failed to load botkey and chatid.");
        return PAM_AUTH_ERR;
    }

    // Generate token and send auth link
    generate_token(token, MAX_TOKEN_LENGTH);
    if (send_auth_link(chatid, botkey, token) != 0) {
        log_message("Failed to send authentication link.");
        pam_error(pamh, "Error: Failed to send authentication link. Login denied.");
        return PAM_AUTH_ERR;
    }

    log_message("Authentication link sent. Waiting for user validation.");
    pam_info(pamh, "CODE: Please click the link sent to your Telegram.");
    sleep(10);

    // Validate the token
    if (validate_token(token) != 0) {
        log_message("Token validation failed. Aborting authentication process.");
        pam_error(pamh, "Token validation failed. Login denied.");
        return PAM_AUTH_ERR; // Immediately terminate the authentication process
    }

    log_message("Authentication successful.");
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
