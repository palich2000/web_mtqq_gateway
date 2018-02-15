#include "jlog.h"
#include <sys/types.h>
#include <unistd.h>

void printv_2json_array(json_object * j_aray, const char * template, va_list ap) {
    char buffer[255];
    vsnprintf(buffer, sizeof(buffer) - 1, template, ap);
    buffer[sizeof(buffer) - 1] = 0;
    json_object_array_add(j_aray, json_object_new_string(buffer));
}

void printf_2json_array(json_object * j_aray, const char * template, ... ) {
    va_list arglist;

    va_start(arglist, template);
    printv_2json_array(j_aray, template, arglist);
    va_end(arglist);
}

static
json_object * x_error_to_jsonv(json_object * j_root, int status, int prio, const char * template, va_list ap) {

    if (!j_root)
        j_root = json_object_new_object();

    json_object_object_add(j_root, "status", json_object_new_int(status));

    json_object_object_add(j_root, "id", json_object_new_int(getpid()));

    json_object * j_aray;

    if (!json_object_object_get_ex(j_root, "log", &j_aray)) {
        j_aray =  json_object_new_array();
        json_object_object_add(j_root, "log", j_aray);
    }

    char buffer[255];
    vsnprintf(buffer, sizeof(buffer) - 1, template, ap);
    buffer[sizeof(buffer) - 1] = 0;

    json_object_array_add(j_aray, json_object_new_string(buffer));
    if (prio == LOG_ERR) {
        json_object_object_add(j_root, "error", json_object_new_string(buffer));
    }

    return(j_root);
}

json_object * x_log_to_json(json_object * j_root, int status, int prio, const char * template, ... ) {
    va_list arglist;

    va_start(arglist, template);
    j_root = x_error_to_jsonv(j_root, status, prio, template, arglist);
    va_end(arglist);

    return(j_root);
}
