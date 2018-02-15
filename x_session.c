#define _GNU_SOURCE
#include "x_session.h"
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include "dlog.h"

int works_in_progress = 0;
pthread_mutex_t works_in_progress_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t works_in_progress_cond = PTHREAD_COND_INITIALIZER;

void work_started() {
    pthread_mutex_lock(&works_in_progress_mtx);
    works_in_progress++;
    pthread_mutex_unlock(&works_in_progress_mtx);
}

void work_finished() {
    pthread_mutex_lock(&works_in_progress_mtx);
    works_in_progress--;
    pthread_cond_signal(&works_in_progress_cond);
    pthread_mutex_unlock(&works_in_progress_mtx);
}

void wait_all_works_finished() {
    pthread_mutex_lock(&works_in_progress_mtx);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 3;
    int rc = 0;

    while (works_in_progress > 0 && rc == 0)
        rc = pthread_cond_timedwait(&works_in_progress_cond, &works_in_progress_mtx, &ts);

    if (rc == 0) {
        daemon_log(LOG_INFO, "All works finished");
    } else {
        daemon_log(LOG_ERR, "Not all works finished. %s", strerror(errno));
    }
    pthread_mutex_unlock(&works_in_progress_mtx);
}

unsigned int get_session_id() {
    static unsigned int session_id = 0;
    static pthread_mutex_t session_id_mtx = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&session_id_mtx);
    session_id++;
    pthread_mutex_unlock(&session_id_mtx);
    return(session_id);
}
