#ifndef foodaemonloghfoo
#define foodaemonloghfoo

/* $Id: dlog.h 120 2007-06-11 15:42:47Z lennart $ */

/*
 * This file is part of libdaemon.
 *
 * libdaemon is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * libdaemon is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with libdaemon; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <syslog.h>
#include <stdarg.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

/** \file
 *
 * Contains a robust API for logging messages
 */

/** Specifies where to send the log messages to. The global variable daemon_log_use takes values of this type.
 */
enum daemon_log_flags {
    DAEMON_LOG_SYSLOG = 1,   /**< Log messages are written to syslog */
    DAEMON_LOG_STDERR = 2,   /**< Log messages are written to STDERR */
    DAEMON_LOG_STDOUT = 4,   /**< Log messages are written to STDOUT */
    DAEMON_LOG_AUTO = 8      /**< If this is set a daemon_fork() will
                                  change this to DAEMON_LOG_SYSLOG in
                                  the daemon process. */
};

/** This variable is used to specify the log target(s) to use. Defaults to DAEMON_LOG_STDERR|DAEMON_LOG_AUTO */
extern enum daemon_log_flags daemon_log_use;

/** Specifies the syslog identification, use daemon_ident_from_argv0()
 * to set this to a sensible value or generate your own. */
extern const char* daemon_log_ident;

#if defined(__GNUC__) && ! defined(DAEMON_GCC_PRINTF_ATTR)
/** A macro for making use of GCCs printf compilation warnings */
#define DAEMON_GCC_PRINTF_ATTR(a,b) __attribute__ ((format (printf, a, b)))
#else
#define DAEMON_GCC_PRINTF_ATTR(a,b)
#endif

/** Log a message using printf format strings using the specified syslog priority
 * @param prio The syslog priority (PRIO_xxx constants)
 * @param t,... The text message to log
 */
void daemon_log(int prio, const char* t, ...) DAEMON_GCC_PRINTF_ATTR(2, 3);

/** This variable is defined to 1 iff daemon_logv() is supported.*/
#define DAEMON_LOGV_AVAILABLE 1

/** Same as daemon_logv, but without variadic arguments */
void daemon_logv(int prio, const char* t, va_list ap);

/** Return a sensible syslog identification for daemon_log_ident
 * generated from argv[0]. This will return a pointer to the file name
 * of argv[0], i.e. strrchr(argv[0], '\')+1
 * @param argv0 argv[0] as passed to main()
 * @return The identification string
 */
char *daemon_ident_from_argv0(char *argv0);

unsigned int daemon_log_upto(unsigned int);
unsigned int  log_check_prio(unsigned int priority);
char * daemon_prio_name(unsigned int priority);
unsigned int    daemon_get_prio(void);

void daemon_trace_switch(bool on);
bool daemon_trace_switch_get();
void daemon_enter(const char * func_name, const char* template, ...) DAEMON_GCC_PRINTF_ATTR(2, 3);
void daemon_leave(const char * func_name, const char* template, ...) DAEMON_GCC_PRINTF_ATTR(2, 3);
void daemon_trace(const char * func_name, const char* template, ...) DAEMON_GCC_PRINTF_ATTR(2, 3);
void daemon_trace_indent_reset_after_error();

#ifdef DEBUG
#define DAEMON_TRACE_ENTER(...)    daemon_enter(__FUNCTION__,__VA_ARGS__)
#define DAEMON_TRACE_LEAVE(...)    daemon_leave(__FUNCTION__,__VA_ARGS__)
#define DAEMON_TRACE(...)    daemon_trace(__FUNCTION__,__VA_ARGS__)
#else
#define DAEMON_TRACE_ENTER(...)    ;
#define DAEMON_TRACE_LEAVE(...)    ;
#define DAEMON_TRACE(...)          ;
#endif

#ifdef __cplusplus
}
#endif

#endif
