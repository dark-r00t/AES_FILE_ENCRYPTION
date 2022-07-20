#ifndef FILE_INCLUDED
#define FILE_INCLUDED

#define _GNU_SOURCE

#define RED "\033[0;31m"
#define GREEN "\033[1m\033[32m"
#define CLEAR "\033[0m"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#else
#include <dirent.h>
#endif

//FILE HANDELING
extern void create_bin_file(unsigned char* output_text);
extern char* get_file_name();
#endif
 
