#include <string.h>
#include <strings.h>
#include <alloca.h>
#include "content_types.h"


typedef struct _content_type_t {
    char * ext;
    char * ct;
} content_type_t;

static content_type_t ct_list[] = {
    {".aac", "audio/aac"},
    {".abw", "application/x-abiword"},
    {".arc", "application/octet-stream"},
    {".avi", "video/x-msvideo"},
    {".azw", "application/vnd.amazon.ebook"},
    {".bin", "application/octet-stream"},
    {".bz", "application/x-bzip"},
    {".bz2", "application/x-bzip2"},
    {".csh", "application/x-csh"},
    {".css", "text/css"},
    {".csv", "text/csv"},
    {".doc", "application/msword"},
    {".eot", "application/vnd.ms-fontobject"},
    {".epub", "application/epub+zip"},
    {".gif", "image/gif"},
    {".htm", "text/html"},
    {".html", "text/html"},
    {".ico", "image/x-icon"},
    {".ics", "text/calendar"},
    {".txt", "text/plain"},
    {".jar", "application/java-archive"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".js", "application/javascript"},
    {".json", "application/json"},
    {".mid", "audio/midi"},
    {".midi", "audio/midi"},
    {".mpeg", "video/mpeg"},
    {".mp4", "video/mp4"},
    {".mpkg", "application/vnd.apple.installer+xml"},
    {".odp", "application/vnd.oasis.opendocument.presentation"},
    {".ods", "application/vnd.oasis.opendocument.spreadsheet"},
    {".odt", "application/vnd.oasis.opendocument.text"},
    {".oga", "audio/ogg"},
    {".ogv", "video/ogg"},
    {".ogx", "application/ogg"},
    {".otf", "font/otf"},
    {".png", "image/png"},
    {".pdf", "application/pdf"},
    {".ppt", "application/vnd.ms-powerpoint"},
    {".rar", "application/x-rar-compressed"},
    {".rtf", "application/rtf"},
    {".sh", "application/x-sh"},
    {".svg", "image/svg+xml"},
    {".swf", "application/x-shockwave-flash"},
    {".tar", "application/x-tar"},
    {".tif", "image/tiff"},
    {".tiff", "image/tiff"},
    {".ts", "video/vnd.dlna.mpeg-tts"},
    {".ttf", "font/ttf"},
    {".vsd", "application/vnd.visio"},
    {".wav", "audio/x-wav"},
    {".weba", "audio/webm"},
    {".webm", "video/webm"},
    {".webp", "image/webp"},
    {".woff", "font/woff"},
    {".woff2", "font/woff2"},
    {".xhtml", "application/xhtml+xml"},
    {".xls", "application/vnd.ms-excel"},
    {".xml", "application/xml"},
    {".xul", "application/vnd.mozilla.xul+xml"},
    {".zip", "application/zip"},
    {".3gp", "video/3gpp"},
    {".3g2", "video/3gpp2"},
    {".7z", "application/x-7z-compressed"},
};

const char * ext2ct(const char * filepath) {
    if (filepath) {
        const char * ext = strrchr(filepath, '.');
        if (ext) {
            for (int i = 0; i < sizeof(ct_list) / sizeof(ct_list[0]); i++) {
                if (strcasecmp(ext, ct_list[i].ext) == 0) {
                    return ct_list[i].ct;
                }
            }
        }
    }
    return "application/octet-stream";
}

const char * ct2ext(const char * ct) {
    if (ct) {
        char * tmp = strrchr(ct, ';');
        if (tmp) {
            char * tmp2;
            int len =  tmp - ct;
            tmp2 = alloca(len + 1);
            bzero(tmp2, len + 1);
            strncpy(tmp2, ct, len);
            ct = tmp2;
        }
        for (int i = 0; i < sizeof(ct_list) / sizeof(ct_list[0]); i++) {
            if (strcasecmp(ct, ct_list[i].ct) == 0) {
                return ct_list[i].ext;
            }
        }
    }
    return ".bin";
}
