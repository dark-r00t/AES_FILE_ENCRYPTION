#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"

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

            expanded_keys[bytes_generated++] = expanded_keys[bytes_generated - 16] ^ tmp[a];
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



unsigned char * decrypt(char * input_text, char * key) {// TODO WE'RE GETTING THE KEY BACK INSTEAD OF OUT TEXT???

    unsigned char* output_text = (unsigned char*) malloc(sizeof(unsigned char) * (strlen(input_text) + 1));

    unsigned char expanded_key[176];
    key_expansion((unsigned char *)key, expanded_key);

    int input_length = strlen((const char*) input_text);

    for(int i = 0; i < input_length; i+=AES_128) {
        aes128_decrypt(input_text + i, output_text + i, expanded_key);
    }

    return output_text;
}

void aes128_decrypt(unsigned char* input_text, unsigned char* output_text, unsigned char* key) {

    unsigned char state[16];
    for (int i = 0; i < 16; i++) {
		state[i] = input_text[i];
	}

    add_round_key(state, key+160);
	inverse_mix_columns(state);
	shift_rows_right(state);
	sub_bytes(state);
    shift_rows_right(state);
	sub_bytes(state);

	for (int i = ROUND; i >= 0; i--) {
        add_round_key(state, key + (16 * (i + 1)));
	    inverse_mix_columns(state);
	    shift_rows_right(state);
	    sub_bytes(state);
	}

	add_round_key(state, key);

	for (int i = 0; i < 16; i++) {
		output_text[i] = state[i];
	}
}

void inverse_mix_columns(unsigned char * state) {

    unsigned char tmp[4][4];

    for (int i = 0; i < 16; i++) {

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

    for (int i = 0; i < 16; i++) {

        state[i] = tmp[i / 4][i % 4];
    }
}

void shift_rows_right(unsigned char * state) {

    unsigned char tmp[16];

	tmp[0]  = state[0];  tmp[1]  = state[13]; tmp[2]  = state[10]; tmp[3] = state[7];
	tmp[4]  = state[4];  tmp[5]  = state[1];  tmp[6]  = state[14]; tmp[7] = state[11];
	tmp[8]  = state[8];  tmp[9]  = state[5];  tmp[10] = state[2];  tmp[11] = state[15];
	tmp[12] = state[12]; tmp[13] = state[9];  tmp[14] = state[6];  tmp[15] = state[3];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

//ENCRYPT/DECRYPT
void add_round_key(unsigned char * state, unsigned char * round_key) {

    for (int i = 0; i < AES_128; i++) {

        state[i] ^= round_key[i];
    }
}

void sub_bytes(unsigned char * state) {

    for (int i = 0; i < AES_128; i++) {

        state[i] = (unsigned char) s_box[state[i]];
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
