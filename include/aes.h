#ifndef AES_INCLUDED
#define AES_INCLUDED

#define _GNU_SOURCE

#include <stdint.h>

#define EXIT_SUCCESS 0
#define EXIT_FAIL 1

#define ENCRYPT 0XF
#define DECRYPT 0xFF

#define RED "\033[0;31m"
#define GREEN "\033[1m\033[32m"
#define CLEAR "\033[0m"

#define AES_128 16
#define MAXPWDLEN AES_128
#define ROUND 9 // 10 for 128 (-1 for final)
#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#else
#include <termios.h>
#endif

//ENCRYPT
extern unsigned char* encrypt(char* input_text, char* key);
extern void aes128_encrypt(unsigned char* input_text, unsigned char* key);
extern void key_expansion_run(unsigned char* in, unsigned char i);
extern void key_expansion(unsigned char* input_key, unsigned char* expanded_keys);
extern void shift_rows_left(unsigned char* state);
extern void mix_columns(unsigned char* state);

//DECRYPT
extern unsigned char* decrypt(char* input_text, char* key);
extern void aes128_decrypt(unsigned char* input_text, unsigned char* output_text, unsigned char* key);
extern void inverse_mix_columns(unsigned char * state);
extern void shift_rows_right(unsigned char * state);

//SHARED
extern void initialize_aes_s_box(uint8_t s_box[256]);
extern void add_round_key(unsigned char * state, unsigned char * round_key);
extern void sub_bytes(unsigned char * state);
extern uint8_t xtime(uint8_t x);
extern uint8_t multiply(uint8_t x, uint8_t y);
#endif
