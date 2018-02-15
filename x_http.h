#ifndef X_HTTP_H_INCLUDED
#define X_HTTP_H_INCLUDED

#include <microhttpd.h>
#include "dfork.h"

int
create_response (void *UNUSED(cls),
                 struct MHD_Connection *connection,
                 const char *url,
                 const char *method,
                 const char *UNUSED(version),
                 const char *upload_data,
                 size_t *upload_data_size,
                 void **ptr);
void
request_completed_callback (void *UNUSED(cls),
                            struct MHD_Connection *connection,
                            void **con_cls,
                            enum MHD_RequestTerminationCode UNUSED(toe));

#endif // X_HTTP_H_INCLUDED
