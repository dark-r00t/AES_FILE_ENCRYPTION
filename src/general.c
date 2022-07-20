#include "general.h"
#include "aes.h"

// GENERAL
void print_hex_val(unsigned char c) {

    if (c / 16 < 10)  printf("%c", (c / 16) + '0');
    if (c / 16 >= 10) printf("%c", (c / 16 - 10) + 'A');
    if (c % 16 < 10)  printf("%c", (c % 16) + '0');
    if (c % 16 >= 10) printf("%c", (c % 16 - 10) + 'A');
}

void print_hex_val_DEBUG(unsigned char* str) {
    printf("\nHex:\n");
    for(int i = 0; i < (int) strlen(str); i++) {
        print_hex_val(str[i]);
        printf(" ");
        if((i+1)%16 == 0) printf("\n");
    } 
    //printf("Text:\n%s\n", str); 
}

char * read_file(char * input, unsigned procedure) {

    FILE * input_file;
    if(procedure == ENCRYPT) input_file = fopen(input, "r");
    if(procedure == DECRYPT) input_file = fopen(input, "rb");

    if (!input_file) {
        // ERROR IN fopen(), such a shame...
        printf("File read error. Try again.\n");
        return NULL;
    }

    // LOG THE LENGTH OF THE FILE IN input_file_size
    fseek(input_file, 0, SEEK_END);
    unsigned long input_file_size = ftell(input_file);
    rewind(input_file);

    // THROW ALL THE INFO IN THE TEXT FILE INTO input_text
    char * input_text = (char * ) malloc(2*input_file_size + 1);
    fread(input_text, input_file_size, 1, input_file);
    fclose(input_file);

    input_text[input_file_size] = '\0';// can't be too cautious 

    return input_text;
}

int verify(unsigned procedure) {

    int flag = 0;

    // Verify the user is trying to do what the claim they want to.
    char buffer[4];
    char * type = (char * ) malloc(sizeof(char) * 8);

    if (procedure == ENCRYPT) {

        char tmp[8] = "ENCRYPT\0";
        strncpy(type, tmp, 8);
    } 
    
    else if (procedure == DECRYPT) {

        char tmp[8] = "DECRYPT\0";
        strncpy(type, tmp, 8);
    }

    printf("\nYou chose to %s your file. Is this the correct input? [yes/NO]: ", type);

    // SCAN BUFFER. REMOVES EXCESS INPUT AND ENSURES THE NEXT SCAN IS SAFE
    scanf("%3s", buffer);
    sscanf(buffer, "%s", type);
    char c;
    while ((c = getchar()) != '\n');

    type[4] = '\0';

    // ALLOW THE USER TO TYPE ANY VARTIATION OF YES (in english ofc)
    if (strcmp(type, "yes") != 0 &&
        strcmp(type, "YES") != 0 &&
        strcmp(type, "Y") != 0 &&
        strcmp(type, "y") != 0) {

        flag = 1;
    }

    free(type);

    return flag;
}

ssize_t get_hidden_key (char **pw, size_t sz, int mask, FILE *fp) {

    if (!pw || !sz || !fp) return -1;// validate param inputs

    if (*pw == NULL) {
        void *tmp = realloc (*pw, (sz+1) * sizeof **pw);
        if (!tmp)
            return -1;
        memset (tmp, 0, (sz+1));// initialize memory to 0
        *pw =  (char*) tmp;
    }

    size_t idx = 0;// index, number of chars in read 
    int c = 0;

    struct termios old_kbd_mode;// orig keyboard settings   
    struct termios new_kbd_mode;

    if (tcgetattr (0, &old_kbd_mode)) {// save orig settings   
        fprintf (stderr, "%s%s() error: tcgetattr failed.%s", RED, __func__, CLEAR);
        return -1;
    }// copy old to new
    memcpy (&new_kbd_mode, &old_kbd_mode, sizeof(struct termios));

    new_kbd_mode.c_lflag &= ~(ICANON | ECHO);// new kbd flags
    new_kbd_mode.c_cc[VTIME] = 0;
    new_kbd_mode.c_cc[VMIN] = 1;
    if (tcsetattr (0, TCSANOW, &new_kbd_mode)) {
        fprintf (stderr, "%s%s() error: tcsetattr failed.%s", RED, __func__, CLEAR);
        return -1;
    }

    // read chars from fp, mask if valid char specified
    while (((c = fgetc (fp)) != '\n' && c != EOF && idx < sz) || (idx == sz && c == 127)) {
        if (c != 127) {
            if (31 < mask && mask < 127)// valid ascii char
                fputc (mask, stdout);
            (*pw)[idx++] = c;
        } else if (idx > 0) {// handle backspace (del)   
            if (31 < mask && mask < 127) {
                fputc (0x8, stdout);
                fputc (' ', stdout);
                fputc (0x8, stdout);
            }
            (*pw)[--idx] = 0;
        }
    }

    (*pw)[idx] = 0;// null-terminate 

    // reset original keyboard 
    if (tcsetattr (0, TCSANOW, &old_kbd_mode)) {
        fprintf (stderr, "%s%s() error: tcsetattr failed.%s", RED, __func__, CLEAR);
        return -1;
    }

    if (idx == sz && c != '\n')// warn if pw truncated 
        fprintf (stderr, " (%s%s() warning: truncated at %zu chars.%s)",
                RED, __func__, sz, CLEAR);

    return idx; // number of chars in passwd
}

char * get_key() {

    char* key;
    char password[MAXPWDLEN] = {0};
    char *key_string = password;
    FILE *fp = stdin;
    ssize_t character_count = -1;

    while(character_count < 0) {
        
        while (strlen(key) < MAXPWDLEN) {

            printf("\nPlease enter your unique key: ");
            character_count = get_hidden_key(&key_string, MAXPWDLEN, '*', fp);

            key = (char*) malloc (sizeof(char) * (MAXPWDLEN + 1));

            strcpy(key, key_string);

            unsigned long size = strlen(key);

            for (unsigned long i = size; i < MAXPWDLEN; i++) {
                key[i] = key[i - size];
            }

            if(strlen(key) < MAXPWDLEN) {
                printf("%sERROR: HIT ENTER AND TRY AGAIN!%s", RED, CLEAR);
                char c;
                while ((c = getchar()) != '\n');
                continue;
            }
        }
    }

    key[MAXPWDLEN] = '\0';

    return key;
}
