#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <search.h>
#include <pthread.h>
#include <json-c/json.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/mman.h>
#include <dirent.h>
#include <openssl/md5.h>
#include <pwd.h>
#include <grp.h>
#include <microhttpd.h>
#include <stdatomic.h>
#include <getopt.h>

//#if MHD_VERSION < 0x0000095100
//#error "The required version of the library libmicrohttpd is 0.9.51"
//#endif // MHD_VERSION

#ifdef __GLIBC__
#include <gnu/libc-version.h>
#endif

#include "dlog.h"
#include "dpid.h"
#include "dsignal.h"
#include "dmem.h"
#include "dfork.h"
#include "dexec.h"
#include "dmem.h"
#include "array.h"
#include "ip_acl.h"
#include "dzip.h"
#include "version.h"
#include "jlog.h"
#include "content_types.h"
#include "x_functions.h"
#include "x_http.h"
#include "x_session.h"
#include "mqtt.h"

#define CDIR "./"

access_list_t * acl_main = NULL;
access_list_t * acl_post_files_accept = NULL;

/* forward*/

bool is_folder_exists(const char * folder);
bool is_file_exists(const char * file);

pid_t main_pid = 0;
mtime_t main_start_time = 0;

int web_threads = 2;
const char * application = "web_mtqq_gateway";

static char * progname = NULL;
static char * pathname = NULL;

static char * runas_user = NULL;
static char * runas_group = NULL;

atomic_bool global_run_it = true;

void
my_logger(void * UNUSED(arg), const char * fmt, va_list ap) {
    daemon_logv(LOG_DEBUG, fmt, ap);
}

static void usage() {

    fprintf(stderr, "Usage: %s [-d ] [-f] [-p integer] [-k command] [-w integer] \n", progname);
    fprintf(stderr, "-i syslog and /var/run/pid indent\n");
    fprintf(stderr, "-d debug flag\n");
    fprintf(stderr, "-f run in foreground \n");
    fprintf(stderr, "-p http listen port by default 3000\n");
    fprintf(stderr, "-k send command to daemon (reconfigure,shutdown,restart,check)\n");
    fprintf(stderr, "-w web threads pool size 1..16 by default 2 \n");
    fprintf(stderr, "-o disable TCP_FASTOPEN feature in web server\n");
    fprintf(stderr, "-a add web access rule, ex -a 192.168.0.0/24 by default allow all\n");
    fprintf(stderr, "-u add upload file web interface access rule, ex -a 192.168.0.0/24 by default allow all\n");
    fprintf(stderr, "-U run as user name\n");
    fprintf(stderr, "-z run as group name\n");

    fprintf(stderr, " SIGUSR1 - enable debug mode\n");
    fprintf(stderr, " SIGUSR2 - disable debug mode\n");
    exit(1);
}

enum command_int_t {
    CMD_NONE = 0,
    CMD_RECONFIGURE,
    CMD_SHUTDOWN,
    CMD_RESTART,
    CMD_CHECK,
    CMD_NOT_FOUND = -1,
};

typedef int (* daemon_command_callback_t)(void*);

typedef struct daemon_command_t {
    char * command_name;
    daemon_command_callback_t  command_callback;
    int command_int;
} DAEMON_COMMAND_T;

int check_callback(void * UNUSED(param)) {
    return(10);
}


int reconfigure_callback(void * UNUSED(param)) {

    if (daemon_pid_file_kill(SIGUSR1) < 0) {
        daemon_log(LOG_WARNING, "Failed to reconfiguring");
    } else {
        daemon_log(LOG_INFO, "OK");
    }
    return(10);
}

int shutdown_callback(void * UNUSED(param)) {
    int ret;
    daemon_log(LOG_INFO, "Try to shutdown self....");
    if ((ret = daemon_pid_file_kill_wait(SIGINT, 10)) < 0) {
        daemon_log(LOG_WARNING, "Failed to shutdown daemon %d %s", errno, strerror(errno));
        daemon_log(LOG_WARNING, "Try to terminating self....");
        if (daemon_pid_file_kill_wait(SIGKILL, 0) < 0) {
            daemon_log(LOG_WARNING, "Failed to killing daemon %d %s", errno, strerror(errno));
        } else {
            daemon_log(LOG_WARNING, "Daemon terminated");
        }
    } else
        daemon_log(LOG_INFO, "OK");
    return(10);
}

int restart_callback(void * UNUSED(param)) {
    shutdown_callback(NULL);
    return(0);
}

DAEMON_COMMAND_T daemon_commands[] = {
    {command_name: "reconfigure", command_callback: reconfigure_callback, command_int: CMD_RECONFIGURE},
    {command_name: "shutdown", command_callback: shutdown_callback, command_int: CMD_SHUTDOWN},
    {command_name: "restart", command_callback: restart_callback, command_int: CMD_RESTART},
    {command_name: "check", command_callback: check_callback, command_int: CMD_CHECK},
};

gid_t get_gid_by_name(const char *name) {
    struct group *grp = getgrnam(name);
    if(grp == NULL) {
        daemon_log(LOG_ERR, "Failed to get groupId from groupname : %s", name);
        return -1;
    }
    return grp->gr_gid;
}

uid_t get_uid_by_name(const char *name) {
    struct passwd *pwd = getpwnam(name);
    if(pwd == NULL) {
        daemon_log(LOG_ERR, "Failed to get userId from username : %s", name);
        return -1;
    }
    return pwd->pw_uid;
}

int bcd2dec(int c) {
    unsigned char dec;

    dec = (c >> 4) & 0x07;
    dec = 10 * dec + (c & 0x0F);
    return dec;
}

int get_file_gid(const char * fn) {
    struct stat sb = {0};
    if (lstat(fn, &sb) != -1 ) {
        return sb.st_gid;
    }
    daemon_log(LOG_ERR, "%s %s %s", __FUNCTION__, fn, strerror(errno));
    return -1;
}

uid_t runas_uid = -1;
uid_t runas_gid = -1;

const char *daemon_pid_file_proc_custom(void) {
    static char fn[PATH_MAX];
    const char * tmp_p = daemon_pid_file_ident ? daemon_pid_file_ident : "unknown";
    snprintf(fn, sizeof(fn), "%s/%s", "/var/run", tmp_p);
    if (!is_directory_exist(fn)) {
        if (mkdir(fn, 0700) == -1) {
            daemon_log(LOG_ERR, "%s %s %s", __FUNCTION__, fn, strerror(errno));
        }
    }
    int gid = get_file_gid(fn);
    if (gid != -1) {
        if (chown(fn, runas_uid, (gid_t) gid) == -1) {
            daemon_log(LOG_ERR, "%s %s %s", __FUNCTION__, fn, strerror(errno));
        }
    }
    snprintf(fn, sizeof(fn), "%s/%s/%s.pid", "/var/run", tmp_p, tmp_p);
    return fn;
}

int
main (int argc, char *const *argv) {
    int listen_port = 3003;
    int daemonize = true;
    int debug = 0;
    char * command = NULL;
    pid_t pid;

    unsigned int fast_open_flag =
#ifdef MHD_USE_TCP_FASTOPEN
        MHD_USE_TCP_FASTOPEN;
#else
        0;
#endif

    MHD_socket old_listen_socket = MHD_INVALID_SOCKET;

    struct MHD_Daemon *d;

    int    fd, sel_res;

    daemon_pid_file_ident = daemon_log_ident = application;
    daemon_pid_file_proc = daemon_pid_file_proc_custom;

    tzset();

    if ((progname = strrchr(argv[0], '/')) == NULL)
        progname = argv[0];
    else
        ++progname;

    if (strrchr(argv[0], '/') == NULL)
        pathname = xstrdup(CDIR);
    else {
        pathname = xmalloc(strlen(argv[0]) + 1);
        strncpy(pathname, argv[0], (strrchr(argv[0], '/') - argv[0]) + 1);
    }
    if (chdir(pathname) < 0) {
        daemon_log(LOG_ERR, "chdir error: %s", strerror(errno));
    }
    FREE(pathname);

    pathname = get_current_dir_name();

    daemon_log_upto(LOG_INFO);
    daemon_log(LOG_INFO, "%s %s", pathname, progname);

    acl_main = access_list_create();
    acl_post_files_accept = access_list_create();


    static struct option long_options[] = {
        /* These options set a flag. */
        {"debug",   no_argument,       0, 'd'},
        {"no-fast-open",   no_argument,   0, 'o'},
        {"run-as-user",    required_argument,       0, 'U'},
        {"run-as-group",   required_argument,       0, 'g'},
        {"acl-mail",  required_argument,       0, 'a'},
        {"acl-post",  required_argument, 0, 'u'},

        {"ident",  required_argument, 0, 'i'},
        {"foreground",    no_argument, 0, 'f'},

        {"debug",    no_argument, 0, 'd'},
        {"command",    required_argument, 0, 'k'},
        {"listen-port",    required_argument, 0, 'p'},
        {"web-threads",    required_argument, 0, 'w'},


        {"mqtt-host",    required_argument, 0, 'M'},
        {"mqtt-port",    required_argument, 0, 'P'},
        {"mqtt-user",    required_argument, 0, 'Z'},
        {"mqtt-password",    required_argument, 0, 'A'},
        {0, 0, 0, 0}
    };
    while (true) {
        int option_index = 0;

        int c = getopt_long (argc, argv, "a:u:i:ofdk:p:w:g:U:P:M:Z:A:",
                             long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'M': {
            mqtt_host = strdup(optarg);
            break;
        }
        case 'Z': {
            mqtt_username = strdup(optarg);
            break;
        }
        case 'A': {
            mqtt_password = strdup(optarg);
            break;
        }
        case 'P': {
            mqtt_port = atoi(optarg);
            if ((mqtt_port < 1) || (mqtt_port > 65535)) {
                daemon_log(LOG_ERR, "Port must be in range 1..65535");
                usage();
            }
            break;
        }
        case 'g': {
            runas_group = strdup(optarg);
            break;
        }
        case 'U': {
            runas_user = strdup(optarg);
            break;
        }
        case 'a': {
            if (!access_list_add_rule(acl_main, optarg, true)) {
                daemon_log(LOG_ERR, "Error in access list rule %s", optarg);
                usage();
            }
            break;
        }
        case 'u': {
            if (!access_list_add_rule(acl_post_files_accept, optarg, true)) {
                daemon_log(LOG_ERR, "Error in access list rule %s", optarg);
                usage();
            }
            break;
        }
        case 'i': {
            daemon_pid_file_ident = daemon_log_ident = xstrdup(optarg);
            break;
        }
        case 'o' : {
            fast_open_flag = 0;
            break;
        }
        case 'f' : {
            daemonize = false;
            break;
        }
        case 'd': {
            debug++;
            daemon_log_upto(LOG_DEBUG);
            break;
        }
        case 'k': {
            command = xstrdup(optarg);
            break;
        }
        case 'p': {
            listen_port = atoi(optarg);
            if ((listen_port < 1) || (listen_port > 65535)) {
                daemon_log(LOG_ERR, "Port must be in range 1..65535");
                usage();
            }
            break;
        }
        case 'w': {
            web_threads = atoi(optarg);
            if ((web_threads < 1) || (web_threads > 16)) {
                daemon_log(LOG_ERR, "web thread pool out of range 1..16");
                usage();
            }
            break;
        }
        case '?':
        default: {
            usage();
            break;
        }

        }
    }

    if (!mqtt_username) {
	daemon_log(LOG_ERR, "Need mqtt username.");
	usage();
    }

    if (!mqtt_password) {
	daemon_log(LOG_ERR, "Need mqtt password.");
	usage();
    }

    if (runas_group) {
        runas_gid = get_gid_by_name(runas_group);
        if (runas_gid == -1 ) exit(1);
    }


    if (runas_user) {
        runas_uid = get_uid_by_name(runas_user);
        if (runas_uid == -1 ) exit(1);
    }

    daemon_log(LOG_INFO, "main acl:");
    access_list_print(acl_main);
    daemon_log(LOG_INFO, "post files acl:");
    access_list_print(acl_post_files_accept);

    if (debug) {
        daemon_log(LOG_DEBUG,    "**************************");
        daemon_log(LOG_DEBUG,    "* WARNING !!! Debug mode *");
        daemon_log(LOG_DEBUG,    "**************************");
    }

    daemon_log(LOG_INFO, "***************************************************************************");
    daemon_log(LOG_INFO, "%s ver %s [%s %s %s] started", application,  git_version, git_branch, __DATE__, __TIME__);
    daemon_log(LOG_INFO, "%s ver %02d.%02d.%02d", "libmicrohttpd", bcd2dec((MHD_VERSION & 0xff000000) >> 24), bcd2dec((MHD_VERSION & 0xff0000) >> 16), bcd2dec((MHD_VERSION & 0xff00) >> 8));
    daemon_log(LOG_INFO, "GNU libc compile-time version: %u.%u", __GLIBC__, __GLIBC_MINOR__);
    daemon_log(LOG_INFO, "GNU libc runtime version:      %s", gnu_get_libc_version());
    daemon_log(LOG_INFO, "***************************************************************************");
    daemon_log(LOG_INFO, "pid file: %s", daemon_pid_file_proc());

    if (command) {
        int r = CMD_NOT_FOUND;
        for (unsigned int i = 0; i < (sizeof(daemon_commands) / sizeof(daemon_commands[0])); i++) {
            if ((strcasecmp(command, daemon_commands[i].command_name) == 0) && (daemon_commands[i].command_callback)) {
                if ((r = daemon_commands[i].command_callback(pathname)) != 0) exit(abs(r - 10));
            }
        }
        if (r == CMD_NOT_FOUND) {
            fprintf(stderr, "command \"%s\" not found.\n", command);
            usage();
        }
    }
    FREE(command);

    /* initialize PRNG */
    srand ((unsigned int) time (NULL));

    if ((pid = daemon_pid_file_is_running()) >= 0) {
        daemon_log(LOG_ERR, "Daemon already running on PID file %u", pid);
        return 1;
    }

    daemon_log(LOG_INFO, "Make a daemon");

    daemon_retval_init();
    if ((daemonize) && ((pid = daemon_fork()) < 0)) {
        return 1;
    } else if ((pid) && (daemonize)) {
        int ret;
        if ((ret = daemon_retval_wait(20)) < 0) {
            daemon_log(LOG_ERR, "Could not recieve return value from daemon process.");
            return 255;
        }
        if (ret == 0) {
            daemon_log(LOG_INFO, "Daemon started.");
        } else {
            daemon_log(LOG_ERR, "Daemon dont started, returned %i as return value.", ret);
        }
        return ret;
    } else {

        if ((runas_group) && (setgid(runas_gid))) {
            daemon_log(LOG_ERR, "error set gid %s: %s", runas_group, strerror(errno));
            goto finish;
        }

        if ((runas_user) && (setuid(runas_uid))) {
            daemon_log(LOG_ERR, "error set uid %s: %s", runas_user, strerror(errno));
            goto finish;
        }
        umask(0022);
        if (daemon_pid_file_create() < 0) {
            daemon_log(LOG_ERR, "Could not create PID file (%s).", strerror(errno));
            daemon_retval_send(1);
            goto finish;
        }

        if (daemon_signal_init(/*SIGCHLD,*/SIGINT, SIGTERM, SIGQUIT, SIGHUP, SIGUSR1, SIGUSR2, SIGHUP, /*SIGSEGV,*/ 0) < 0) {
            daemon_log(LOG_ERR, "Could not register signal handlers (%s).", strerror(errno));
            daemon_retval_send(1);
            goto finish;
        }

        daemon_retval_send(0);
        daemon_log(LOG_INFO, "%s ver %s [%s %s %s] started", application,  git_version, git_branch, __DATE__, __TIME__);

        struct rlimit core_lim;

        if (getrlimit(RLIMIT_CORE, &core_lim) < 0) {
            daemon_log(LOG_ERR, "getrlimit RLIMIT_CORE error:%s", strerror(errno));
        } else {
            daemon_log(LOG_INFO, "core limit is cur:%2ld max:%2ld", core_lim.rlim_cur, core_lim.rlim_max );
            core_lim.rlim_cur = -1;
            core_lim.rlim_max = -1;
            if (setrlimit(RLIMIT_CORE, &core_lim) < 0) {
                daemon_log(LOG_ERR, "setrlimit RLIMIT_CORE error:%s", strerror(errno));
            } else {
                daemon_log(LOG_INFO, "core limit set cur:%2ld max:%2ld", core_lim.rlim_cur, core_lim.rlim_max );
            }
        }
        main_pid = syscall(SYS_gettid);
        main_start_time = mtime_now();

        mosq_init(progname);

        d = MHD_start_daemon (MHD_USE_DEBUG | MHD_USE_SELECT_INTERNALLY | MHD_USE_POLL | MHD_USE_PIPE_FOR_SHUTDOWN | fast_open_flag,
                              listen_port,
                              NULL, NULL,
                              &create_response, NULL,
                              MHD_OPTION_THREAD_POOL_SIZE, (unsigned int) web_threads,
                              MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 15,
                              MHD_OPTION_NOTIFY_COMPLETED, &request_completed_callback, NULL,
                              MHD_OPTION_EXTERNAL_LOGGER, &my_logger, "tester",
                              MHD_OPTION_END);
        if (NULL == d) {
            daemon_log(LOG_ERR, "Error MHD_start_daemon %d %s", errno, strerror(errno));
            goto finish;
        } else {
            daemon_log(LOG_INFO, "MHD_start_daemon on port:%d OK", listen_port);
        }

        fd_set fds;
        FD_ZERO(&fds);
        fd = daemon_signal_fd();
        FD_SET(fd,  &fds);

        while (global_run_it) {
            struct timeval tv;
            tv.tv_sec  = 0;
            tv.tv_usec = 100000;
            fd_set fds2 = fds;
            if ((sel_res = select(FD_SETSIZE, &fds2, 0, 0, &tv)) < 0) {

                if (errno == EINTR)
                    continue;

                daemon_log(LOG_ERR, "select() error:%d %s", errno,  strerror(errno));
                break;
            }
            if (FD_ISSET(fd, &fds2)) {
                int sig;

                if ((sig = daemon_signal_next()) <= 0) {
                    daemon_log(LOG_ERR, "daemon_signal_next() failed.");
                    break;
                }

                switch (sig) {
                case SIGCHLD: {
                    int ret = 0;
                    daemon_log(LOG_INFO, "SIG_CHLD");
                    wait(&ret);
                    daemon_log(LOG_INFO, "RET=%d", ret);
                }
                break;

                case SIGINT:
                case SIGQUIT:
                case SIGTERM:
                    daemon_log(LOG_WARNING, "Got SIGINT, SIGQUIT or SIGTERM");
                    global_run_it = false;
                    if (d) {
                        daemon_log(LOG_WARNING, "Stop accepting connections");
                        old_listen_socket = MHD_quiesce_daemon(d);
                    }
                    break;

                case SIGUSR1: {
                    daemon_log(LOG_WARNING, "Got SIGUSR1");
                    daemon_log(LOG_WARNING, "Enter in debug mode, to stop send me USR2 signal");
                    daemon_log_upto(LOG_DEBUG);
                    break;
                }
                case SIGUSR2: {
                    daemon_log(LOG_WARNING, "Got SIGUSR2");
                    daemon_log(LOG_WARNING, "Leave debug mode");
                    daemon_log_upto(LOG_INFO);
                    break;
                }
                case SIGHUP:
                    daemon_log(LOG_WARNING, "Got SIGHUP");
                    break;

                case SIGSEGV:
                    daemon_log(LOG_ERR, "Seg fault. Core dumped to /tmp/core.");
                    if (chdir("/tmp") < 0) {
                        daemon_log(LOG_ERR, "Chdir to /tmp error: %s", strerror(errno));
                    }
                    signal(sig, SIG_DFL);
                    kill(getpid(), sig);
                    break;

                default:
                    daemon_log(LOG_ERR, "UNKNOWN SIGNAL:%s", strsignal(sig));
                    break;

                }
            }
        }

        wait_all_works_finished();
        MHD_stop_daemon (d);

        if (old_listen_socket != MHD_INVALID_SOCKET) {
            close(old_listen_socket);
        }

    }

finish:
    access_list_destroy(&acl_main);
    access_list_destroy(&acl_post_files_accept);
    daemon_log(LOG_INFO, "Exiting...");
    mosq_destroy();
    FREE(runas_user);
    FREE(runas_group);
    FREE(pathname);
    daemon_retval_send(-1);
    daemon_signal_done();
    daemon_pid_file_remove();
    daemon_log(LOG_INFO, "Exit");
    exit(0);
}
