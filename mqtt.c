#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <mosquitto.h>
#include <pthread.h>
#include "dlog.h"

//------------------------------------------------------------------------------------------------------------
//
// Mosquitto:
//
//------------------------------------------------------------------------------------------------------------
static bool mqtt_stop = false;

typedef struct _client_info_t {
    struct mosquitto *m;
    pid_t pid;
    uint32_t tick_ct;
} t_client_info;

char * mqtt_host = "localhost";
char * mqtt_username = NULL;
char * mqtt_password = NULL;
int mqtt_port = 8883;
int mqtt_keepalive = 60;

static struct mosquitto *mosq = NULL;
static t_client_info client_info;
static pthread_t mosq_th = 0;

int mosq_publish_json(const char * topic, const char * data, bool retain) {
    int res;
    if ((res = mosquitto_publish (mosq, NULL, topic, strlen (data), data, 0, retain)) != 0) {
        daemon_log(LOG_ERR, "Can't publish to Mosquitto server %s", mosquitto_strerror(res));
    } else {
        daemon_log(LOG_INFO, "%s %s %s", topic, data, retain ? "-" : "r");
    }
    return res;
}




void on_log(struct mosquitto *mosq, void *userdata, int level, const char *str) {
    switch(level) {
//    case MOSQ_LOG_DEBUG:
//    case MOSQ_LOG_INFO:
//    case MOSQ_LOG_NOTICE:
    case MOSQ_LOG_WARNING:
    case MOSQ_LOG_ERR: {
        daemon_log(LOG_ERR, "%i:%s", level, str);
    }
    }
}

static
void on_connect(struct mosquitto *m, void *udata, int res) {
    if (res == 0) {             /* success */
        //t_client_info *info = (t_client_info *)udata;
        //mosquitto_subscribe(m, NULL, "home/+/weather/#", 0);
        //mosquitto_subscribe(m, NULL, "stat/+/POWER", 0);
	daemon_log(LOG_INFO, "mqtt connected");
    } else {
        daemon_log(LOG_ERR, "mqtt connection error: (%d) %s", res, mosquitto_strerror(res));
	sleep(5);
    }
}

static
void on_publish(struct mosquitto *m, void *udata, int m_id) {
    //daemon_log(LOG_ERR, "-- published successfully");
}

static
void on_subscribe(struct mosquitto *m, void *udata, int mid,
                  int qos_count, const int *granted_qos) {
    daemon_log(LOG_INFO, "-- subscribed successfully");
}

static
void on_message(struct mosquitto *m, void *udata,
                const struct mosquitto_message *msg) {
    if (msg == NULL) {
        return;
    }
    daemon_log(LOG_INFO, "-- got message @ %s: (%d, QoS %d, %s) '%s'",
               msg->topic, msg->payloadlen, msg->qos, msg->retain ? "R" : "!r",
               (char*)msg->payload);

    /*
    int ret = regexec(&mqtt_topic_regex, msg->topic, 0, NULL, 0);
    if (!ret) {
        daemon_log(LOG_INFO, "--  Accept message");
        char * topic_copy = strdupa(msg->topic);
        char * start = strchr(topic_copy, '/');
        char * end = strrchr(topic_copy, '/');
        if (start != end) {
            *end = 0;
            start++;
            asprintf(&mqtt_display1, "%s", start);
            asprintf(&mqtt_display2, "%s", (char*)msg->payload);
            DispMode = 5;
        }
    } else if (ret == REG_NOMATCH) {
        daemon_log(LOG_INFO, "--  Skip message");
    } else {
        char msgbuf[100] = {};
        regerror(ret, &mqtt_topic_regex, msgbuf, sizeof(msgbuf));
        daemon_log(LOG_ERR, "Regex match failed: %s", msgbuf);
    }
    */
    //t_client_info *info = (t_client_info *)udata;
}

static
void * mosq_thread_loop(void * p) {
    t_client_info *info = (t_client_info *)p;
    daemon_log(LOG_INFO, "%s", __FUNCTION__);
    while (!mqtt_stop) {
        int res = mosquitto_loop(info->m, 1000, 1);
        switch (res) {
        case MOSQ_ERR_SUCCESS:
            break;
        case MOSQ_ERR_NO_CONN: {
            int res = mosquitto_connect (mosq, mqtt_host, mqtt_port, mqtt_keepalive);
            if (res) {
                daemon_log(LOG_ERR, "Can't connect to Mosquitto server %s", mosquitto_strerror(res));
		sleep(10);
            }
            break;
        }
        case MOSQ_ERR_INVAL:
        case MOSQ_ERR_NOMEM:
        case MOSQ_ERR_CONN_LOST:
        case MOSQ_ERR_PROTOCOL:
        case MOSQ_ERR_ERRNO:
            daemon_log(LOG_ERR, "%s %s %s", __FUNCTION__, strerror(errno), mosquitto_strerror(res));
            break;
        }
    }
    daemon_log(LOG_INFO, "%s finished", __FUNCTION__);
    pthread_exit(NULL);
}

void mosq_init(const char * progname) {

    bool clean_session = true;

    mosquitto_lib_init();

    mosq = mosquitto_new(progname, clean_session, &client_info);
    if(!mosq) {
        daemon_log(LOG_ERR, "mosq Error: Out of memory.");
    } else {
        client_info.m = mosq;
        mosquitto_log_callback_set(mosq, on_log);

        mosquitto_connect_callback_set(mosq, on_connect);
        mosquitto_publish_callback_set(mosq, on_publish);
        mosquitto_subscribe_callback_set(mosq, on_subscribe);
        mosquitto_message_callback_set(mosq, on_message);

        mosquitto_username_pw_set (mosq, mqtt_username, mqtt_password);

        daemon_log(LOG_INFO, "Try connect to Mosquitto server %s:%d ", mqtt_host, mqtt_port);
        int res = mosquitto_connect (mosq, mqtt_host, mqtt_port, mqtt_keepalive);
        if (res) {
            daemon_log(LOG_ERR, "Can't connect to Mosquitto server %s", mosquitto_strerror(res));
        }
        mqtt_stop = false;
        pthread_create(&mosq_th, NULL, mosq_thread_loop, &client_info);
    }

}

void mosq_destroy() {
    mqtt_stop = true;
    pthread_join(mosq_th, NULL);
    if (mosq) {
        mosquitto_disconnect(mosq);
        mosquitto_destroy(mosq);
    }
    mosquitto_lib_cleanup();
}
