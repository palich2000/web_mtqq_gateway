#ifndef X_FUNCTIONS_H_INCLUDED
#define X_FUNCTIONS_H_INCLUDED
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef int64_t mtime_t;

mtime_t mtime_now();
void no_free(void **p);
bool end_with(const char * path, const char * ext);
int remove_directory(const char *path);

bool is_folder_exists(const char * folder);
bool is_file_exists(const char * file);
int file_size(const char * file); //ret -1 if error

int fcopy(FILE* src_fd, FILE* dst_fd);
#endif // X_FUNCTIONS_H_INCLUDED
