#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ip_acl.h"
#include "dmem.h"
#include "dlog.h"

static
in_addr_t netmask( int prefix ) {

    if ( prefix == 0 )
        return( ~((in_addr_t) - 1) );
    else
        return( htonl(~((1 << (32 - prefix)) - 1) ));
}

static
in_addr_t network( in_addr_t addr, int prefix ) {

    return( addr & netmask(prefix) );

} /* network() */

access_list_t * access_list_create() {
    access_list_t * acl = xmalloc(sizeof(* acl));
    acl->rules = array_create();
    return(acl);
}

void access_list_destroy(access_list_t ** acl) {
    if ((!acl) || (!*acl)) return;
    array_destroy(&((*acl)->rules), NULL, NULL);
    FREE(*acl);
}

bool access_list_add_rule(access_list_t * acl, const char * _ipstr, bool allow) {
    if ((!acl) || (!acl->rules) || (!_ipstr)) return(false);
    access_rule_t * rule;

    long int prefix = 32;
    char * prefixstr;
    char * ipstr = strdupa(_ipstr);

    if ( (prefixstr = strchr(ipstr, '/')) ) {
        *prefixstr = '\0';
        prefixstr++;
        errno = 0;
        prefix = strtol( prefixstr, (char **) NULL, 10 );
        if ( errno || (*prefixstr == '\0') || (prefix < 0) || (prefix > 32) ) {
            daemon_log(LOG_ERR, "Invalid prefix /%s...!  %d(%s)", prefixstr, errno, strerror(errno));
            return(false);
        }
    }


    in_addr_t mask = netmask(prefix);
    in_addr_t addr = inet_addr(ipstr);

    if (addr == INADDR_NONE) return(false);

    addr = network(addr, prefix);

    rule = xmalloc(sizeof(*rule));
    rule->addr = addr;
    rule->mask = mask;
    rule->allow = allow;
    array_append(acl->rules, rule);
    return(true);
}

bool access_list_check(access_list_t * acl, in_addr_t addr) {
    if ((!acl) || (!acl->rules)) return(false);
    if (array_getcount(acl->rules) == 0) return(true);

    array_for_each(acl->rules, i) {
        access_rule_t * rule = array_getitem(acl->rules, i);
        if (rule) {
            if ((addr & rule->mask) == rule->addr) {
                return(rule->allow);
            }
        }
    }

    return(false);
}

void access_list_print(access_list_t * acl) {
    if (!acl) return;
    array_for_each(acl->rules, i) {
        access_rule_t * rule = array_getitem(acl->rules, i);
        if (rule) {
            char * s_addr = strdupa(inet_ntoa(*(struct in_addr*)&rule->addr));
            char * s_mask = strdupa(inet_ntoa(*(struct in_addr*)&rule->mask));
            daemon_log(LOG_INFO, "%s %s %s",
                       s_addr,
                       s_mask,
                       rule->allow ? "allow" : "deny");
        }
    }
}


