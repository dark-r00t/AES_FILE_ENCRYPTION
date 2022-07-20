#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"
#include "file.h"
#include "general.h"
#include "leak_detector_c.h"

int main(int argc, char ** argv) {

    atexit(report_mem_leak);

    // Log the desired procedure if any.
    unsigned procedure = 0;

    // The user did not use the correct arguments. 
    if (argc != 3) {
        if (argc < 3) printf("Please include a file name and a procedure flag.\n");
        else printf("Please only include a file name and procedure flag.");
        printf("Run the file with the -h flag to receive HELP.\n");
        return EXIT_FAIL;
    }

    // Check if the help flag was used.
    if (strcmp("-h", argv[1]) == 0) {
        printf(" -h\tHelp\n -e\tEncrypt\n -d\tDecrypt\n\n Example: ./run -e input.txt\n");
        return EXIT_SUCCESS;
    }

    // Analyze the users input flags.
    if (strcmp("-e", argv[1]) == 0) procedure = ENCRYPT;
    else if (strcmp("-d", argv[1]) == 0) procedure = DECRYPT;
    else {
        printf("Bad flag. Use the -h flag to receive HELP.\n");
        return EXIT_FAIL;
    }

    // Verify the user is trying to do what the claim they want to.
    if (verify(procedure)) return EXIT_FAIL;

    char * input_text = read_file(argv[2], procedure);
    if (!input_text) return EXIT_FAIL;

    char * key = get_key();

    // Do the expected procedure.
    unsigned char * output_text;
    if (procedure == ENCRYPT) {
        output_text = encrypt(input_text, key);
    } else {
        output_text = decrypt(input_text, key);
    }

    // Uh-oh.
    if (!output_text) return EXIT_FAIL;

    // Create the Encrypted/Decrypted file using the resultant output text data.
    create_bin_file(output_text);

    free(input_text);
    free(key);
    free(output_text);
    
    printf("\nSuccess.\n");
    return EXIT_SUCCESS;
} 
