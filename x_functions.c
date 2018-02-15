#define _GNU_SOURCE
#include "x_functions.h"
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "dlog.h"


int fcopy(FILE *src, FILE *dst) {
    char            buffer[2048];
    size_t          n;

    while ((n = fread(buffer, sizeof(char), sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, sizeof(char), n, dst) != n)
            return -1;
    }
    return 0;
}

mtime_t mtime_now() {
    struct timeval tv;
    gettimeofday( &tv, NULL );
    return(((mtime_t)tv.tv_sec * 1000) + ((mtime_t)tv.tv_usec / 1000));
}

void no_free(void **p) {
}

int remove_directory(const char *path) {
    DIR *d = opendir(path);
    size_t path_len = strlen(path);
    int r = -1;

    if (d) {
        daemon_log(LOG_INFO, "removing %s", path);
        struct dirent *p;

        r = 0;

        while (!r && (p = readdir(d))) {
            int r2 = -1;
            char *buf;
            size_t len;

            /* Skip the names "." and ".." as we don't want to recurse on them. */
            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) {
                continue;
            }

            len = path_len + strlen(p->d_name) + 2;
            buf = malloc(len);

            if (buf) {
                struct stat statbuf;

                snprintf(buf, len, "%s/%s", path, p->d_name);

                if (!stat(buf, &statbuf)) {
                    if (S_ISDIR(statbuf.st_mode)) {
                        r2 = remove_directory(buf);
                    } else {
                        r2 = unlink(buf);
                    }
                }

                free(buf);
            }

            r = r2;
        }

        closedir(d);
    }

    if (!r) {
        r = rmdir(path);
    }

    return r;
}


bool end_with(const char * path, const char * ext) {
    if ((!path) || (!ext)) return(false);

    if (strlen(path) < strlen(ext)) return(false);

    const char * path_p = path + strlen(path) - 1;
    const char * ext_p = ext + strlen(ext) - 1;
    while (ext_p >= ext) {
        if (*path_p != *ext_p) return(false);
        path_p--;
        ext_p--;
    }
    return(true);
}

bool is_folder_exists(const char * folder) {
    struct stat sb = {0};
    if (lstat(folder, &sb) == -1) {
        return(false);
    } else {
        return(true);
    }
}

bool is_file_exists(const char * file) {
    struct stat sb = {0};
    if (lstat(file, &sb) == -1) {
        return(false);
    } else {
        if(S_ISREG(sb.st_mode)) {
            return(true);
        }
        return(false);
    }
}

int file_size(const char * file) {
    if (is_file_exists(file)) {
        struct stat sb = {0};
        if (lstat(file, &sb) == -1) {
            return -1;
        }
        return sb.st_size;
    }
    return -1;
}
