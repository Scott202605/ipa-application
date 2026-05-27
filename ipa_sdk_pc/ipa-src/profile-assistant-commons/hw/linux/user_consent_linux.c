/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#ifdef SUPPORT_USER_CONSENT_INTERFACE
#include <stdio.h>
#include <errno.h>
#include <sys/select.h>
#include <unistd.h>
#include "user_consent.h"
#include "log.h"

#define INPUT_KEYBOARD_BUFFER_SIZE 64
#define USER_CONSENT_QUESTION "[yes/no/not now]"

#define USER_CONSENT_ACCEPT_STR_1 "yes\n"
#define USER_CONSENT_ACCEPT_STR_2 "Yes\n"
#define USER_CONSENT_ACCEPT_STR_3 "YES\n"

#define USER_CONSENT_REJECT_STR_1 "no\n"
#define USER_CONSENT_REJECT_STR_2 "No\n"
#define USER_CONSENT_REJECT_STR_3 "NO\n"

#define USER_CONSENT_POSTPONED_STR_1 "not now\n"
#define USER_CONSENT_POSTPONED_STR_2 "Not now\n"
#define USER_CONSENT_POSTPONED_STR_3 "NOT NOW\n"

user_consent_result_t user_consent__request(const char* title, unsigned int timeout) {
    int result = 0;
    char buffer[INPUT_KEYBOARD_BUFFER_SIZE] = { 0 };
    ssize_t num_bytes;
    
    // Loop to read and handle the input events.
    fd_set read_fds;
    struct timeval tv = {
        .tv_sec = timeout,
        .tv_usec = 0
    };
    FD_ZERO(&read_fds);
    FD_SET(STDIN_FILENO, &read_fds);

    
    /* Ask the question to the user */
    printf("\n%s [timeout=%us] %s\r\n", title, timeout, USER_CONSENT_QUESTION);

    // This will set up an interruption until an event happen on SDTIN or until "tv" timed out
    result = select(FD_SETSIZE, &read_fds, NULL, NULL, &tv);
    if (result < 0) {
        if (errno != EINTR) {
            LOGE("[user_consent__request] Error in select(): %d %s", result, strerror(errno));
            return USER_CONSENT_REJECTED;
        }
    } else if (result > 0) {
        // If the event happened on the SDTIN
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            num_bytes = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
            if (num_bytes >= 0) {
                // Handle the stdin in case an enter is detected
                if (0 == strcmp(USER_CONSENT_ACCEPT_STR_1, buffer) || 
                    0 == strcmp(USER_CONSENT_ACCEPT_STR_2, buffer) ||
                    0 == strcmp(USER_CONSENT_ACCEPT_STR_3, buffer)) {
                    LOGI("End user consent accepted.");
                    return USER_CONSENT_ACCEPTED;
                } else if (0 == strcmp(USER_CONSENT_REJECT_STR_1, buffer) || 
                    0 == strcmp(USER_CONSENT_REJECT_STR_2, buffer) ||
                    0 == strcmp(USER_CONSENT_REJECT_STR_3, buffer)) {
                    LOGI("End user consent rejected.");
                    return USER_CONSENT_REJECTED;
                } else if (0 == strcmp(USER_CONSENT_POSTPONED_STR_1, buffer) || 
                    0 == strcmp(USER_CONSENT_POSTPONED_STR_2, buffer) ||
                    0 == strcmp(USER_CONSENT_POSTPONED_STR_3, buffer)) {
                    LOGI("End user consent postponed.");
                    return USER_CONSENT_POSTPONED;
                }
            }
            
        }
    }
    LOGW("[user_consent__request] Timeout reached");

    return USER_CONSENT_TIMEOUT;
}
#endif
