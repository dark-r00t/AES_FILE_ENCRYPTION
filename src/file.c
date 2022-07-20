#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "file.h"

void create_bin_file(unsigned char * output_text) {

    char* output_file_name = get_file_name();

    if(!output_file_name) return;

    printf("\n\n%s%s%s\n", GREEN, output_file_name, CLEAR);// color coded print of the new files name.

    FILE * output_file = fopen(output_file_name, "wb");
    fprintf(output_file, "%s", output_text);
    fclose(output_file);
    
    free(output_file_name);
}                           

// TODO SHOVE TEXT FILE INTO output/ DIRECTORY. 
// IF THERES NO output/ DIRECTORY SIMPLY JUMP TO THE ELSE AFTER THE FOR LOOP

char* get_file_name() {
#if !defined(WIN32) || !defined(_WIN32) || !defined(__WIN32)
    char* outputName = (char*) malloc(sizeof(char) * 29); //aes128_encrypted_text###.bin\0    
    struct dirent **namelist;
    int n = scandir(".", &namelist, NULL, alphasort);// get a list of files in the CWD and store the file count in 'n'

    if(n<0) {// error getting directory information
        return NULL;
    }

    int number = -1;// used to store the highest number, for making the directory name
    char val[4];// used to store the highest number, for making the directory name
    for(int i = 2; i < n; i++) {// i = 2, to ignore . and ..
        if(strlen(namelist[i]->d_name) >= 24) {// check to see if the file can be aes128_encrypted_text### (for out of bounds assurance)
            
            memcpy(outputName, &namelist[i]->d_name, 21);//get the first 21 letters of the string in namelist
            
            if (strcmp(outputName, "aes128_encrypted_text") == 0) {// we found an existing aes128_encrypted_text file
                
                char tmpv[4]; tmpv[3] = '\0'; 
                memcpy(tmpv, &namelist[i]->d_name[21],3);// copy the ### number (i.e. >>001<<)
                
                if(tmpv[0] < '0' || tmpv[0] > '9') continue;// this file doesnt follow our format (i.e. aes128_encrypted_text.bin)
                for(int j = 0; j < 3; j++) if(tmpv[j] < '0' || tmpv[j] > '9') goto CONTINUE;

                int tempi = atoi(tmpv);
                if(tempi > number) {// we found the next highest value (i.e. 001 -> 002)

                    if(number != -1 && tempi-number != 1) break;// we found a gap (i.e. 001 -> 004)                         
                    number = tempi;// update with new highest number (int)
                    strcpy(val, tmpv);//update with new highest number (str)
                }
            }
        }
        CONTINUE:
    }
    
    number++; // this is the new number we will use (i.e. 002->003)

    if(number >= 1000) return NULL; // if the new number is too large.

    if(number) {// check to see if we ever actually found an aes128_encrypted_text###.bin file

        sprintf(val, "%d", number);// convert the number into string format
        int len = strlen(val);// see how many leading zero's are required
        switch(len) {// generate leading zero('s) and add the digit(s)
            case 1: outputName[22] = '0';
            case 2: outputName[21] = '0';
        }

        strcat(outputName, val);
        strcat(outputName, ".bin\0");// finalize the documents name
    } else {// there was no aes128_encrypted_text###.bin file found. create the first one.
        strcpy(outputName, "aes128_encrypted_text000.bin\0");
    }

    while(n--) {
        free(namelist[n]);
    } free(namelist);

    return outputName;
#endif
}
