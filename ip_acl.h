#ifndef fooipaclh
#define fooipaclh
#include "array.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

typedef struct _access_rule_t {
    in_addr_t mask;
    in_addr_t addr;
    bool      allow;
} access_rule_t;

typedef struct _access_list_t {
    array_t * rules;
} access_list_t;

access_list_t * access_list_create();
void access_list_destroy(access_list_t **);
bool access_list_add_rule(access_list_t * acl, const char * ipstr, bool allow);
bool access_list_check(access_list_t * acl, in_addr_t addr);
void access_list_print(access_list_t * acl);
#endif // fooipaclh
