#ifndef GENERAL_INCLUDED
#define GENERAL_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "file.h"

char* read_file(char* input, unsigned procedure);
int verify(unsigned procedure);
char* get_key();
ssize_t get_hidden_key (char **pw, size_t sz, int mask, FILE *fp);
void print_hex_val(unsigned char c);
void print_hex_DEBUG(unsigned char* str);

#endif
