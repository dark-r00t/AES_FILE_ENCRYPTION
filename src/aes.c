#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"
#include "general.h"

static unsigned char rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

uint8_t s_box[256];

unsigned char inv_s[256] = { // TODO
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

unsigned char * encrypt(char * input_text, char * key) {

    int input_length = strlen((const char * ) input_text);
    int padded_length = input_length;

    if (padded_length % 16 != 0) {

        padded_length = (padded_length / 16 + 1) * 16;
    }

    unsigned char * padded_text = (unsigned char * ) malloc(sizeof(unsigned char) * padded_length);
    for (int i = 0; i < padded_length; i++) {
        
        if (i >= input_length) {

            padded_text[i] = 0;
        } 
        
        else {

            padded_text[i] = input_text[i];
        }
    }

    initialize_aes_s_box(s_box);

    for (int i = 0; i < padded_length; i += AES_128) {

        aes128_encrypt(padded_text + i, (unsigned char * ) key);
    }

    return padded_text;
}

void aes128_encrypt(unsigned char * input_text, unsigned char * key) {

    unsigned char state[AES_128];
    for (int i = 0; i < AES_128; i++) {

        state[i] = input_text[i];
    }

    // EXPAND THE KEYS
    unsigned char expanded_key[176];
    key_expansion(key, expanded_key);

    // INITIAL ROUND
    add_round_key(state, key);

    for (int i = 0; i < ROUND; i++) {

        sub_bytes(state);
        shift_rows_left(state);
        mix_columns(state);
        add_round_key(state, expanded_key + (16 * (i + 1)));
    }

    //FINAL ROUND
    sub_bytes(state);
    shift_rows_left(state);
    add_round_key(state, expanded_key + 160);

    for (int i = 0; i < AES_128; i++) {

        input_text[i] = state[i];
    }
}

void initialize_aes_s_box(uint8_t s_box[256]) {

    uint8_t p = 1, q = 1;

    do {p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;

        uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

        s_box[p] = xformed ^ 0x63;

    } while (p != 1);

    s_box[0] = 0x63;
}

void key_expansion_run(unsigned char * in , unsigned char i) {

    // ROTATE LEFT
    unsigned char tmp;
    tmp    = in [0]; 
    in [0] = in [1]; 
    in [1] = in [2]; 
    in [2] = in [3]; 
    in [3] = tmp;

    in [0] = s_box[ in [0]]; 
    in [1] = s_box[ in [1]]; 
    in [2] = s_box[ in [2]]; 
    in [3] = s_box[ in [3]];

    // RCON
    in [0] ^= rcon[i];
}

void key_expansion(unsigned char * input_key, unsigned char * expanded_keys) {

    // FIRST 16 BYTES OF THE ORIGINAL KEY
    for (int i = 0; i < AES_128; i++) {

        expanded_keys[i] = input_key[i];
    }

    // 
    int bytes_generated = AES_128;
    int rcon_iter = 1;
    unsigned char tmp[4];

    while (bytes_generated < 176) {

        for (int i = 0; i < 4; i++) {

            tmp[i] = expanded_keys[i + bytes_generated - 4];
        }

        // RUN ONCE PER 16 BYTES
        if (bytes_generated % 16 == 0) {

            key_expansion_run(tmp, rcon_iter++);
        }

        for (unsigned char a = 0; a < 4; a++) {

            expanded_keys[bytes_generated] = expanded_keys[bytes_generated - 16] ^ tmp[a];
            bytes_generated++;
        }
    }
}

void shift_rows_left(unsigned char * state) {

    unsigned char tmp[16];

    tmp[0]  = state[0];  tmp[1]  = state[5];  tmp[2]  = state[10]; tmp[3] = state[15];
    tmp[4]  = state[4];  tmp[5]  = state[9];  tmp[6]  = state[14]; tmp[7] = state[3];
    tmp[8]  = state[8];  tmp[9]  = state[13]; tmp[10] = state[2];  tmp[11] = state[7];
    tmp[12] = state[12]; tmp[13] = state[1];  tmp[14] = state[6];  tmp[15] = state[11];

    for (int i = 0; i < AES_128; i++) {

        state[i] = tmp[i];
    }
}

void mix_columns(unsigned char * state) {

    unsigned char tmp[4][4];

    for (int i = 0; i < 16; i++) {

        tmp[i / 4][i % 4] = state[i];
    }

    unsigned char alpha, beta, gamma;
    for (int i = 0; i < 4; ++i) {

        gamma = tmp[i][0];
        
        alpha = tmp[i][0] ^ tmp[i][1] ^ tmp[i][2] ^ tmp[i][3];
        
        beta = tmp[i][0] ^ tmp[i][1]; beta = xtime(beta); tmp[i][0] ^= beta ^ alpha;
        beta = tmp[i][1] ^ tmp[i][2]; beta = xtime(beta); tmp[i][1] ^= beta ^ alpha;
        beta = tmp[i][2] ^ tmp[i][3]; beta = xtime(beta); tmp[i][2] ^= beta ^ alpha;
        beta = tmp[i][3] ^ gamma;     beta = xtime(beta); tmp[i][3] ^= beta ^ alpha;
    }

    for (int i = 0; i < 16; i++) {

        state[i] = tmp[i / 4][i % 4];
    }
}

void sub_bytes(unsigned char * state) {

    for (int i = 0; i < AES_128; i++) {

        state[i] = (unsigned char) s_box[state[i]];
    }
}

unsigned char * decrypt(char * input_text, char * key) {

    int input_length = strlen((const char*) input_text);
    unsigned char* output_text = (unsigned char*) malloc(sizeof(unsigned char) * (input_length + 1));

    unsigned char expanded_key[176];
    key_expansion((unsigned char *)key, expanded_key);

    for(int i = 0; i < input_length; i+=AES_128) {
        aes128_decrypt(input_text + i, output_text + i, expanded_key);
    }

    printf("\n%s", output_text); print_hex_val_DEBUG(output_text);

    return output_text;
}

void aes128_decrypt(unsigned char* input_text, unsigned char* output_text, unsigned char* key) {// TODO

    unsigned char state[AES_128];
    for (int i = 0; i < AES_128; i++) {
		state[i] = input_text[i];
	}

    add_round_key(state, key+160);
	shift_rows_right(state);
	sub_inverse_bytes(state);

    for (int i = ROUND-1; i >= 0; i--) {
        add_round_key(state, key + (AES_128 * (i + 1)));
        inverse_mix_columns(state);
        shift_rows_right(state);
        sub_inverse_bytes(state);
    }

    add_round_key(state, key);

	for (int i = 0; i < AES_128; i++) {
		output_text[i] = state[i];
	}
}

void inverse_mix_columns(unsigned char * state) {

    unsigned char tmp[4][4];

    for (int i = 0; i < AES_128; i++) {

        tmp[i / 4][i % 4] = state[i];
    }

    uint8_t alpha, beta, gamma, theta;
    for (int i = 0; i < 4; ++i) { 
      alpha = tmp[i][0];
      beta  = tmp[i][1];
      gamma = tmp[i][2];
      theta = tmp[i][3];
  
      tmp[i][0] = multiply(alpha, 0x0e) ^ multiply(beta, 0x0b) ^ multiply(gamma, 0x0d) ^ multiply(theta, 0x09);
      tmp[i][1] = multiply(alpha, 0x09) ^ multiply(beta, 0x0e) ^ multiply(gamma, 0x0b) ^ multiply(theta, 0x0d);
      tmp[i][2] = multiply(alpha, 0x0d) ^ multiply(beta, 0x09) ^ multiply(gamma, 0x0e) ^ multiply(theta, 0x0b);
      tmp[i][3] = multiply(alpha, 0x0b) ^ multiply(beta, 0x0d) ^ multiply(gamma, 0x09) ^ multiply(theta, 0x0e);
    }

    for (int i = 0; i < AES_128; i++) {

        state[i] = tmp[i / 4][i % 4];
    }
}

void shift_rows_right(unsigned char * state) {

    unsigned char tmp[AES_128];

	tmp[0]  = state[0];  tmp[1]  = state[13]; tmp[2]  = state[10]; tmp[3] =  state[7];
	tmp[4]  = state[4];  tmp[5]  = state[1];  tmp[6]  = state[14]; tmp[7] =  state[11];
	tmp[8]  = state[8];  tmp[9]  = state[5];  tmp[10] = state[2];  tmp[11] = state[15];
	tmp[12] = state[12]; tmp[13] = state[9];  tmp[14] = state[6];  tmp[15] = state[3];

	for (int i = 0; i < AES_128; i++) {
		state[i] = tmp[i];
	}
}

void sub_inverse_bytes(unsigned char * state) {// TODO

    for (int i = 0; i < AES_128; i++) {

        state[i] = (unsigned char) inv_s[state[i]];
    }
}

//ENCRYPT/DECRYPT
void add_round_key(unsigned char * state, unsigned char * round_key) {

    for (int i = 0; i < AES_128; i++) {

        state[i] ^= round_key[i];
    }
}

uint8_t xtime(uint8_t x) {
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

uint8_t multiply(uint8_t x, uint8_t y) {
    //https://github.com/kokke/tiny-AES-c/blob/master/aes.c
    return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
}
