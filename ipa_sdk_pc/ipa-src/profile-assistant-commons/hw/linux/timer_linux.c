/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <time.h>
#include <unistd.h>

#include "timer.h"
#include "log.h"

time_data timer__get_time_data() {
    time_t time_stamp = time(NULL); 
    struct tm* tm = localtime(&time_stamp);
    time_data t_d = {.day = tm->tm_mday, .month = tm->tm_mon+1, .year = tm->tm_year+1900, .hour = tm->tm_hour, .minute = tm->tm_min, .second = tm->tm_sec};
    return t_d; 
}

int timer__get_clock_data(clock_data_t *clock_data) {
    struct timespec current;

    if (NULL == clock_data) {
        LOGE("[timer__get_clock_data]\tclock_data instance is null");
        return -eBadArg;
    }

    clock_gettime(CLOCK_MONOTONIC, &current);
    clock_data->tv_sec = current.tv_sec;
    clock_data->tv_nsec = current.tv_nsec;
    return 0; 
}

void timer__sleep(unsigned int seconds) {
    sleep(seconds);
}
