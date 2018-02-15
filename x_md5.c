#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/md5.h>
#include "dlog.h"
#include "dmem.h"

char * calc_md5_str(char * data) {
    char * ret = NULL;
    if (data) {
        int n;
        MD5_CTX md5_ctx;
        char md5_str[33] = {};
        unsigned char digest[16];

        MD5_Init(&md5_ctx);

        MD5_Update(&md5_ctx, data, strlen(data));

        MD5_Final(digest, &md5_ctx);

        for (n = 0; n < 16; ++n) {
            snprintf(&(md5_str[n * 2]), 16 * 2, "%02x", (unsigned int)digest[n]);
        }
        ret = strdup(md5_str);
    }
    return(ret);
}

char * calc_md5_file(char * file_name) {
    char * ret = NULL;
    if (file_name) {
        FILE *fp = NULL;
        if (NULL != (fp = fopen (file_name, "rb"))) {
            int n, err = 0;
            size_t readed, fsize = 0;
            MD5_CTX md5_ctx;
            char md5_str[33] = {};
            unsigned char digest[16];

            MD5_Init(&md5_ctx);
            while (!feof(fp)) {
                char buffer[1024];
                readed = fread(buffer, 1, sizeof(buffer), fp);
                if (readed) {
                    fsize += readed;
                    MD5_Update(&md5_ctx, buffer, readed);
                }
                if (readed != sizeof(buffer)) break;
            }
            daemon_log(LOG_INFO, "readed:%ld bytes", fsize );
            MD5_Final(digest, &md5_ctx);
            if (err) {
                daemon_log(LOG_ERR, "Error while reading file %s (%d)%s", file_name, err, strerror(err));
            } else {
                for (n = 0; n < 16; ++n) {
                    snprintf(&(md5_str[n * 2]), 16 * 2, "%02x", (unsigned int)digest[n]);
                }
                ret = strdup(md5_str);
            }
            fclose(fp);
        }
    }
    return(ret);
}
