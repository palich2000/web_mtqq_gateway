#ifndef _MQTT_H
#define _MQTT_H

extern char * mqtt_host;
extern char * mqtt_username;
extern char * mqtt_password;
extern int mqtt_port;

void mosq_init(const char * progname);
void mosq_destroy();
int mosq_publish_json(const char * topic, const char * data, bool retain);

#endif //_MQTT_H