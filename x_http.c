#define _GNU_SOURCE
#include <stdio.h>
#include <json-c/json.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>
#include <openssl/md5.h>

#include "x_http.h"
#include "x_functions.h"
#include "dlog.h"
#include "dmem.h"
#include "jlog.h"
#include "ip_acl.h"
#include "content_types.h"
#include "x_session.h"
#include "x_md5.h"
#include "mqtt.h"

#define POSTBUFFERSIZE  512

extern access_list_t * acl_main;
extern access_list_t * acl_post_files_accept;

typedef struct _kv_pair_t {
    char * key;
    char * value;
} kv_pair_t;

kv_pair_t * kv_pair_new(const char * key, const char * value) {
    kv_pair_t * ret = xmalloc(sizeof(*ret));
    if (ret) {
        ret->key = strdup(key);
        ret->value = strdup(value);
    }
    return(ret);
}

void kv_pair_destroy(void ** v) {
    if ((!v) || (!*v)) return;
    kv_pair_t ** val = (kv_pair_t **)v;
    FREE((*val)->key);
    FREE((*val)->value);
    FREE((*val));
}


typedef struct _request_t {
    const char *post_url;

    unsigned int session;
    mtime_t create_time;

    struct MHD_PostProcessor *postprocessor;

    json_object * ret_json;

    array_t * params;

} request_t;

request_t * request_new() {
    request_t * ret = xmalloc(sizeof(*ret));
    if (ret) {
        ret->params = array_create();
    }
    return(ret);
}

void request_destroy(request_t ** request) {

    if (!request || !*request) return;
    array_destroy(&(*request)->params, NULL, kv_pair_destroy);
    FREE(*request);
}

const char * get_value_by_key(request_t * request, const char * key) {
    char * ret = NULL;
    if ((!request) || (!request->params)) return(ret);
    array_for_each(request->params, i) {
        kv_pair_t * item = array_getitem(request->params, i);
        if ((item->key) && (key) && (strcmp(key, item->key) == 0)) {
            ret = item->value;
            break;
        }
    }
    return ret;
}


typedef int (*create_request_t)(struct MHD_Connection *, request_t **ptr, const char * method, const char * url);

typedef int (*handle_request_t)(struct MHD_Connection *, request_t **ptr, const char * method, const char * url, size_t * upload_data_size, const char *upload_data);

typedef struct _url_handler_t {
    const char * url;
    regex_t url_regex;
    bool is_regex;
    create_request_t create_request;
    handle_request_t handle_request_post;
    handle_request_t handle_request_get;
} url_handler_t;

/**
 * Invalid method page.
 */
const char *METHOD_ERROR  =  "{\"status\":404,\"errors\":[{\"code\":\"Invalid method.\"}]}";

/**
 * Invalid URL page.
 */
const char *NOT_FOUND_ERROR = "{\"status\":404,\"errors\":[{\"code\":\"Page not found\"}]}";

/**
 * Access denied  URL page.
 */
const char *ACCESS_DENIED_ERROR  = "{\"status\":403,\"errors\":[{\"code\":\"Access denied.\"}]}";

/**
 * Last page.
 */
#define LAST_PAGE "{\"status\":200,\"errors\":[{\"code\":\"It works!\"}]}"


const char *upload_file_form = "<html><body>\n\
                       Upload a file, please!<br>\n\
                       <form action=\"/filepost\" method=\"post\" enctype=\"multipart/form-data\">\n\
                       md5<input name=\"md5\" type=\"text\"><br>\n\
                       dst_path<input name=\"dst_path\" type=\"text\"><br>\n\
                       <input name=\"file\" type=\"file\"><br>\n\
                       <input type=\"submit\" value=\" Send \"></form>\n\
                       </body></html>";



typedef int (*PageHandler)(const void *cls,
                           const char *mime,
                           struct MHD_Connection *connection);


struct Page {
    const char *url;
    const char *mime;
    PageHandler handler;
    const void *handler_cls;
};

/******************************************************************************************************************/
/*   Send simple from via http                                                                                    */
/******************************************************************************************************************/

static int
serve_simple_form (const void *cls,
                   const char *mime,
                   struct MHD_Connection *connection) {
    int ret;
    const char *form = cls;
    struct MHD_Response *response;

    response = MHD_create_response_from_buffer (strlen (form),
               (void *) form,
               MHD_RESPMEM_PERSISTENT);
    if (NULL == response)
        return MHD_NO;
    MHD_add_response_header (response,
                             MHD_HTTP_HEADER_CONTENT_TYPE,
                             mime);
    ret = MHD_queue_response (connection,
                              MHD_HTTP_OK,
                              response);
    MHD_destroy_response (response);
    return ret;
}


/******************************************************************************************************************/
/*   Send 404 page via http                                                                                       */
/******************************************************************************************************************/

static int
not_found_page (const void *UNUSED(cls),
                const char *mime,
                struct MHD_Connection *connection) {
    int ret;
    struct MHD_Response *response;

    response = MHD_create_response_from_buffer (strlen (NOT_FOUND_ERROR),
               (void *) NOT_FOUND_ERROR,
               MHD_RESPMEM_PERSISTENT);

    if (NULL == response)
        return MHD_NO;

    ret = MHD_queue_response (connection,
                              MHD_HTTP_NOT_FOUND,
                              response);

    MHD_add_response_header (response,
                             MHD_HTTP_HEADER_CONTENT_ENCODING,
                             mime);

    MHD_destroy_response (response);
    if (ret != MHD_YES)
        daemon_log(LOG_ERR, "%s----------------------------------- MHD_queue_response ERROR", __FUNCTION__);
    return ret;
}

/******************************************************************************************************************/
/*   Send json via http                                                                                           */
/******************************************************************************************************************/

static int
send_json_page (json_object *j_root,
                const char *mime,
                struct MHD_Connection *connection) {
    int ret;
    struct MHD_Response *response;

    const char * str_json = json_object_to_json_string_ext(j_root, JSON_C_TO_STRING_PLAIN);
    response = MHD_create_response_from_buffer (strlen (str_json),
               (void *) str_json,
               MHD_RESPMEM_MUST_COPY);

    if (NULL == response)
        return MHD_NO;

    ret = MHD_queue_response (connection,
                              MHD_HTTP_OK,
                              response);

    MHD_add_response_header (response,
                             MHD_HTTP_HEADER_CONTENT_TYPE,
                             mime);

    MHD_destroy_response (response);
    if (ret != MHD_YES)
        daemon_log(LOG_ERR, "%s----------------------------------- MHD_queue_response ERROR", __FUNCTION__);
    return ret;
}

static
struct Page pages[] = {
    { url: "/", mime: "application/json", handler:&serve_simple_form, handler_cls: LAST_PAGE},
    { url: NULL, mime: "text/html", handler:&not_found_page, handler_cls: NULL } /* 404 */
};

/******************************************************************************************************************/
/*   Send page via http from char * buffer                                                                        */
/******************************************************************************************************************/

static int
send_page (struct MHD_Connection *connection,
           const char *page,
           int status_code) {
    int ret;
    struct MHD_Response *response;

    response =
        MHD_create_response_from_buffer (strlen (page),
                                         (void *) page,
                                         MHD_RESPMEM_MUST_COPY);
    if (!response) {
        daemon_log(LOG_ERR, "error in %s at line %d", __FUNCTION__, __LINE__);
        return MHD_NO;
    }
    MHD_add_response_header (response,
                             MHD_HTTP_HEADER_CONTENT_TYPE,
                             "text/html");
    ret = MHD_queue_response (connection,
                              status_code,
                              response);
    MHD_destroy_response (response);

    return ret;
}

/******************************************************************************************************************/
/*   Create response from file                                                                                    */
/******************************************************************************************************************/

static
struct MHD_Response * MHD_create_response_from_file(const char* path) {
    struct stat fileStats;

    int fileDescriptor = open(path, O_RDONLY);

    if (fileDescriptor < 0) {
        daemon_log(LOG_ERR, "file %s open error: %s", path, strerror(errno));
        return NULL;
    }

    if (fstat(fileDescriptor, &fileStats) != 0) {
        if (close(fileDescriptor) != 0) {
            daemon_log(LOG_ERR, "stat file %s error: %s", path, strerror(errno));
        }

        return NULL;
    }

    struct MHD_Response* result = MHD_create_response_from_fd_at_offset64(fileStats.st_size,
                                  fileDescriptor,
                                  0);
    return result;
}

/******************************************************************************************************************/
/*   Send file via http                                                                                           */
/******************************************************************************************************************/

static int
send_file (struct MHD_Connection *connection,
           const char *file,
           const char * ct) {
    int ret;
    struct MHD_Response *response;

    response = MHD_create_response_from_file(file);
    if (!response)
        return MHD_NO;
    MHD_add_response_header (response,
                             MHD_HTTP_HEADER_CONTENT_TYPE,
                             ct);
    ret = MHD_queue_response (connection,
                              MHD_HTTP_OK,
                              response);
    MHD_destroy_response (response);

    return ret;
}

/******************************************************************************************************************/
/*   Send form for sending file                                                                                   */
/******************************************************************************************************************/

int handle_request_get_upload(struct MHD_Connection * connection, request_t **request, const char * method, const char * url, size_t * upload_data_size, const char *upload_data) {
    struct sockaddr_in * addr_in = (struct sockaddr_in *) MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
    if (!access_list_check(acl_post_files_accept, addr_in->sin_addr.s_addr)) {
        daemon_log(LOG_ERR, "Access denied: %s %d", inet_ntoa((addr_in->sin_addr)), __LINE__);
        return(send_page(connection, ACCESS_DENIED_ERROR, MHD_HTTP_FORBIDDEN));
    }
    return(send_page(connection, upload_file_form, MHD_HTTP_OK));
}


static int
log_key (void *cls, enum MHD_ValueKind kind, const char *key,
         const char *value) {
    daemon_log(LOG_INFO, "%d %s: %s", kind, key, value);
    return MHD_YES;
}

/******************************************************************************************************************/
/*   Iterator for /mqtt                                                                                           */
/******************************************************************************************************************/

static int
iterate_post_mqtt (void *coninfo_cls,
                   enum MHD_ValueKind kind,
                   const char *key,
                   const char *filename,
                   const char *content_type,
                   const char *transfer_encoding,
                   const char *data,
                   uint64_t off,
                   size_t size) {

    request_t *request = coninfo_cls;
    //daemon_log(LOG_INFO, "%s: %s %lu", key, data, size);
    array_append(request->params, kv_pair_new(key, data));
    return MHD_YES;
}

/******************************************************************************************************************/
/*   Handling GET request for url /mqtt                                                                           */
/******************************************************************************************************************/

int create_request_mqtt(struct MHD_Connection * connection, request_t **request, const char * method, const char * url) {

    struct sockaddr_in * addr_in = (struct sockaddr_in *) MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;

    daemon_log(LOG_DEBUG, __FUNCTION__ );

    if (0 == strcasecmp (method, MHD_HTTP_METHOD_POST)) {
        if (!access_list_check(acl_post_files_accept, addr_in->sin_addr.s_addr)) {
            daemon_log(LOG_ERR, "Access denied: %s %d", inet_ntoa((addr_in->sin_addr)), __LINE__);
            (*request)->ret_json = x_log_to_json((*request)->ret_json, MHD_HTTP_FORBIDDEN, LOG_ERR, "Access denied");
            return MHD_NO;
        }
        (*request)->postprocessor =
            MHD_create_post_processor (connection,
                                       POSTBUFFERSIZE,
                                       &iterate_post_mqtt,
                                       (void *) *request);

        if (NULL == (*request)->postprocessor) {
            daemon_log(LOG_INFO, "[%s:%d][%08u] [NEW] %s %s install MHD_create_post_processor error",
                       inet_ntoa(addr_in->sin_addr), ntohs(addr_in->sin_port), (*request)->session, method, url
                      );
            FREE(*request);
            return MHD_NO;
        } else {
            daemon_log(LOG_INFO, "[%s:%d][%08u] [NEW] %s %s install MHD_create_post_processor OK",
                       inet_ntoa(addr_in->sin_addr), ntohs(addr_in->sin_port), (*request)->session, method, url
                      );
        }

    }
    return MHD_YES;
}


/******************************************************************************************************************/
/*   Handling GET request for url /mqtt                                                                           */
/******************************************************************************************************************/

int handle_request_mqtt_get(struct MHD_Connection * connection, request_t **request, const char * method, const char * url, size_t * upload_data_size, const char *upload_data) {

    char * src_url =  NULL;
    char * context_type = NULL;

    daemon_log(LOG_DEBUG, __FUNCTION__ );

    void destroy_all_locals() {
        FREE(src_url);
        FREE(context_type);
    }

    MHD_get_connection_values (connection, MHD_GET_ARGUMENT_KIND, log_key, NULL);

    //const char* arg_src_url = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "url");

    (*request)->ret_json = x_log_to_json((*request)->ret_json, 404, LOG_ERR, "ALL OK");
    destroy_all_locals();
    return(send_json_page((*request)->ret_json, "application/json", connection));
}

/******************************************************************************************************************/
/*   Handling POST request for url /mqtt                                                                          */
/******************************************************************************************************************/

int handle_request_mqtt_post(struct MHD_Connection * connection, request_t **request, const char * method, const char * url, size_t * upload_data_size, const char *upload_data) {
    daemon_log(LOG_DEBUG, "%s ds:%lu", __FUNCTION__, *upload_data_size);

    struct sockaddr_in * addr_in = (struct sockaddr_in *) MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;

    if (0 != *upload_data_size) {
        if (!access_list_check(acl_post_files_accept, addr_in->sin_addr.s_addr)) {
            daemon_log(LOG_ERR, "Access denied: %s %d", inet_ntoa((addr_in->sin_addr)), __LINE__);
            *upload_data_size = 0;
            return(send_page(connection, ACCESS_DENIED_ERROR, MHD_HTTP_FORBIDDEN));
        }
        {
            if (MHD_post_process ((*request)->postprocessor, upload_data, *upload_data_size) == MHD_YES) {
                *upload_data_size = 0;
                return MHD_YES;
            } else {
                daemon_log(LOG_ERR, "MHD_post_process return fail");
            }
            *upload_data_size = 0;
            return MHD_YES;
        }

        // Data received, parse
        /*
        */
    } else {
        // Work !
        daemon_log(LOG_DEBUG, "---------------------------- %s ds:%lu", __FUNCTION__, *upload_data_size);
        void destroy_all_locals() {
        }

        const char * topic = get_value_by_key(*request, "topic");
        const char * data_json = get_value_by_key(*request, "data");
        const char * retain_str = get_value_by_key(*request, "retain");
        const char * md5_protect = get_value_by_key(*request, "md5");
        bool retain_flag = false;

        if (retain_str) {
            retain_flag = atoi(retain_str);
        }
        if (!topic) {
            (*request)->ret_json = x_log_to_json((*request)->ret_json, 500, LOG_ERR, "Fatal, topic parameter not found");
        } else {
            if (!data_json) {
                (*request)->ret_json = x_log_to_json((*request)->ret_json, 500, LOG_ERR, "Fatal, data parameter not found");
            } else {
                json_tokener * tokener = json_tokener_new();
                json_object * jobj = json_tokener_parse_ex(tokener, data_json, strlen(data_json));
                enum json_tokener_error jerr = json_tokener_get_error(tokener);

                if (jerr != json_tokener_success) {
                    if (jerr == json_tokener_continue) {
                        daemon_log(LOG_ERR, "Data are not fully received. Waiting for more data ....");
                    } else {
                        daemon_log(LOG_ERR, "Json_tokener_parse_ex jerror:'%s'", json_tokener_error_desc(jerr));
                    }
                    (*request)->ret_json = x_log_to_json((*request)->ret_json, 500, LOG_ERR, "Json_tokener_parse_ex jerror:'%s'", json_tokener_error_desc(jerr));
                } else {
                    bool err = false;
                    if (md5_protect) {
                        MD5_CTX md5_ctx;
                        char md5_str[MD5_DIGEST_LENGTH * 2 + 1] = {};
                        unsigned char digest[MD5_DIGEST_LENGTH];

                        MD5_Init(&md5_ctx);

                        MD5_Update(&md5_ctx, data_json, strlen(data_json));

                        MD5_Final(digest, &md5_ctx);

                        for (int n = 0; n < MD5_DIGEST_LENGTH; ++n) {
                            snprintf(&(md5_str[n * 2]), MD5_DIGEST_LENGTH * 2, "%02x", (unsigned int)digest[n]);
                        }
                        if (strcasecmp(md5_str, md5_protect) != 0) {
                            (*request)->ret_json = x_log_to_json((*request)->ret_json, 500, LOG_ERR, "json protect error");
                            err = true;
                        }
                    }
                    if (!err) {
                        int ret;
                        if ((ret = mosq_publish_json(topic, data_json, retain_flag)) != 0) {
                            (*request)->ret_json = x_log_to_json((*request)->ret_json, 500, LOG_ERR, "MQTT send error: %d", ret);
                        } else {
                            (*request)->ret_json = x_log_to_json((*request)->ret_json, 200, LOG_INFO, "MQTT send OK");
                        }
                    }
                }
                json_tokener_free(tokener);
                json_object_put(jobj);
            }
        }

        destroy_all_locals();
        return(send_json_page((*request)->ret_json, "application/json", connection));
    }
    return MHD_YES;
}

/******************************************************************************************************************/
/*   Url table with handlers                                                                                      */
/******************************************************************************************************************/

url_handler_t url_handlers[] = {
    {
url: "/mqtt"
        ,
create_request:
        create_request_mqtt,
handle_request_get:
        handle_request_mqtt_get,
handle_request_post:
        handle_request_mqtt_post,
    },
};

/******************************************************************************************************************/
/*   HTTP server main loop                                                                                        */
/******************************************************************************************************************/

int
create_response (void *UNUSED(cls),
                 struct MHD_Connection *connection,
                 const char *url,
                 const char *method,
                 const char *UNUSED(version),
                 const char *upload_data,
                 size_t *upload_data_size,
                 void **ptr) {

    struct MHD_Response *response;
    request_t **request;
    int ret;

    request = (request_t **) ptr;

    struct sockaddr_in * addr_in = (struct sockaddr_in *) MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;

    // create new request

    if (NULL == *request) {
        *ptr = *request = request_new();
        if (NULL == *request) {
            daemon_log(LOG_ERR, "calloc error: %s", strerror (errno));
            return MHD_NO;
        } else {
            bool found = false;
            work_started();
            (*request)->session = get_session_id();
            (*request)->create_time = mtime_now();

            for (int i = 0; i < sizeof(url_handlers) / sizeof(url_handlers[0]); i++) {
                if (!url_handlers[i].create_request) continue;
                if (url_handlers[i].is_regex) {
                    int ret = regexec(&url_handlers[i].url_regex, url, 0, NULL, 0);
                    if (!ret) {
                        found = true;
                        int ret = url_handlers[i].create_request(connection, request, method, url);
                        if (MHD_NO == ret) {
                            return ret;
                        }
                        break;
                    } else if (ret == REG_NOMATCH) {
                        ;
                    } else {
                        char msgbuf[100] = {};
                        regerror(ret, &url_handlers[i].url_regex, msgbuf, sizeof(msgbuf));
                        daemon_log(LOG_ERR, "Regex match failed: %s", msgbuf);
                    }
                } else {
                    if ((0 == strcmp(url, url_handlers[i].url)) && (url_handlers[i].create_request)) {
                        found = true;
                        int ret = url_handlers[i].create_request(connection, request, method, url);
                        if (MHD_NO == ret) {
                            return ret;
                        }
                        break;
                    }
                }


            }
            if (!found) {
                daemon_log(LOG_INFO, "[%s:%d][%08u] [NEW] %s %s data size %d",
                           inet_ntoa(addr_in->sin_addr), ntohs(addr_in->sin_port), (*request)->session, method, url,
                           (int)*upload_data_size);
            }
        }
        return MHD_YES;
    } else {
        daemon_log(LOG_DEBUG, "[%s:%d][%08u] [OLD] %s data size %d ",
                   inet_ntoa(addr_in->sin_addr), ntohs(addr_in->sin_port), (*request)->session, method,
                   (int)*upload_data_size);
    }

    // process POST request
    if (0 == strcmp (method, MHD_HTTP_METHOD_POST)) {
        for (int i = 0; i < sizeof(url_handlers) / sizeof(url_handlers[0]); i++) {
            if ((0 == strcmp(url, url_handlers[i].url)) && (url_handlers[i].handle_request_post)) {
                return(url_handlers[i].handle_request_post(connection, request, method, url, upload_data_size, upload_data));
            }

        }
        method = MHD_HTTP_METHOD_GET; /* fake 'GET' */
        if (NULL != (*request)->post_url)
            url = (*request)->post_url;

    } else if (0 == strcmp (method, MHD_HTTP_METHOD_GET)) { // process GET request
        for (int i = 0; i < sizeof(url_handlers) / sizeof(url_handlers[0]); i++) {
            if ((0 == strcmp(url, url_handlers[i].url)) && (url_handlers[i].handle_request_get)) {
                return(url_handlers[i].handle_request_get(connection, request, method, url, upload_data_size, upload_data));
            }
        }
    }

    // send JSON or send default PAGE
    if ( (0 == strcmp (method, MHD_HTTP_METHOD_GET)) || (0 == strcmp (method, MHD_HTTP_METHOD_HEAD)) ) {

        if ((*request)->ret_json) {
            return(send_json_page((*request)->ret_json, "application/json", connection));
        }

        if (*upload_data_size) {
            *upload_data_size = 0;
            return(MHD_YES);
        }

        /* find out which page to serve */
        unsigned int i = 0;
        while ( (pages[i].url != NULL) &&
                (0 != strcmp (pages[i].url, url)) )
            i++;
        ret = pages[i].handler (pages[i].handler_cls,
                                pages[i].mime,
                                connection);
        if (ret != MHD_YES) {
            daemon_log(LOG_ERR, "[%s:%d][%08u] %s Failed to create page for `%s'",
                       inet_ntoa(addr_in->sin_addr), ntohs(addr_in->sin_port), (*request)->session, method,
                       url);
        }
        return ret;
    }

    // unsupported HTTP method
    response = MHD_create_response_from_buffer (strlen (METHOD_ERROR),
               (void *) METHOD_ERROR,
               MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response (connection,
                              MHD_HTTP_NOT_ACCEPTABLE,
                              response);
    MHD_destroy_response (response);
    return ret;
}


/******************************************************************************************************************/
/*   HTTP request finish callback                                                                                 */
/******************************************************************************************************************/

void
request_completed_callback (void *UNUSED(cls),
                            struct MHD_Connection *connection,
                            void **con_cls,
                            enum MHD_RequestTerminationCode UNUSED(toe)) {
    request_t *request = *con_cls;

    if (NULL == request)
        return;

    if (NULL != request->postprocessor) {
        MHD_destroy_post_processor (request->postprocessor);
    }

    struct sockaddr_in * addr_in = (struct sockaddr_in *) MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;

    daemon_log(LOG_INFO, "[%s:%d][%08u] Closed. Duration %lu msec",
               inet_ntoa(addr_in->sin_addr), htons(addr_in->sin_port), request->session,
               mtime_now() - request->create_time);

    json_object_put(request->ret_json);
    request->ret_json = NULL;

    request_destroy(&request);
    work_finished();
}

/******************************************************************************************************************/
/*                                                                                                                */
/******************************************************************************************************************/
void x_http_init() __attribute__ ((constructor));

void x_http_init() {
    for (int i = 0; i < sizeof(url_handlers) / sizeof(url_handlers[0]); i++) {
        if (!url_handlers[i].is_regex) continue;
        daemon_log(LOG_INFO, "Compiling regexp: '%s'", url_handlers[i].url);
        int reti = regcomp(&url_handlers[i].url_regex, url_handlers[i].url, 0);
        if (reti) {
            daemon_log(LOG_ERR, "Could not compile regex '%s'", url_handlers[i].url);
        }
    }
}
