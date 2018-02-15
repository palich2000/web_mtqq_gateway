#ifndef JLOG_H_INCLUDED
#define JLOG_H_INCLUDED

#include <json-c/json.h>
#include <stdio.h>
#include "dlog.h"

void printf_2json_array(json_object * j_aray, const char * template, ... ) DAEMON_GCC_PRINTF_ATTR(2, 3);
json_object * x_log_to_json(json_object * j_root, int status, int prio, const char * template, ... ) DAEMON_GCC_PRINTF_ATTR(4, 5);


#endif // JLOG_H_INCLUDED
