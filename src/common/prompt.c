#include <stdio.h>
#include <string.h>

void prompt_user(const char *prompt, const char *format, void *variable) {
    char input[256]; // user input buffer

    // Show prompt with the default value
    if (strcmp(format, "%d") == 0) {
        printf("%s: (%d) ", prompt, *((int *)variable));
    } else if (strcmp(format, "%s") == 0) {
        printf("%s: (%s) ", prompt, (char *)variable);
    } else {
        printf("%s: ", prompt);
    }

    // Read user input
    fgets(input, sizeof(input), stdin);

    // If input is not just a newline, parse it according to the format
    if (input[0] != '\n' || input[0] != '\0' || input[0] != '\r'){
        sscanf(input, format, variable);
    }
}
