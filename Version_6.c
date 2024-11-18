#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_VARS 100   // Maximum number of variables

struct var {
    char *name;
    char *value;
    int global; // Boolean indicating if it's a global variable (1 for global, 0 for local)
};

// Array to store variables
struct var vars[MAX_VARS];
int var_count = 0;

// Function to add or update a variable
void set_var(const char *name, const char *value, int global) {
    for (int i = 0; i < var_count; i++) {
        if (strcmp(vars[i].name, name) == 0) {
            free(vars[i].value);
            vars[i].value = strdup(value);
            vars[i].global = global;
            return;
        }
    }
    // Add a new variable if it doesn't exist
    if (var_count < MAX_VARS) {
        vars[var_count].name = strdup(name);
        vars[var_count].value = strdup(value);
        vars[var_count].global = global;
        var_count++;
    } else {
        printf("Error: Variable limit reached\n");
    }
}

// Function to get the value of a variable
char *get_var(const char *name) {
    for (int i = 0; i < var_count; i++) {
        if (strcmp(vars[i].name, name) == 0) {
            return vars[i].value;
        }
    }
    return NULL;
}

// Function to handle the "printenc" command
void printenc() {
    for (int i = 0; i < var_count; i++) {
        printf("%s=%s\n", vars[i].name, vars[i].value);
    }
}

// Function to handle the "eco" command with variable substitution
void eco(const char *input) {
    char buffer[256];
    int j = 0;

    for (int i = 0; input[i] != '\0'; i++) {
        if (input[i] == '$' && (i == 0 || input[i-1] == ' ')) {
            // Detect variable substitution
            char var_name[64];
            int k = 0;
            i++; // Skip '$'
            while (input[i] != '\0' && input[i] != ' ' && k < 63) {
                var_name[k++] = input[i++];
            }
            var_name[k] = '\0';

            // Get variable value
            char *value = get_var(var_name);
            if (value) {
                int m = 0;
                while (value[m] != '\0' && j < 255) {
                    buffer[j++] = value[m++];
                }
            } else {
                // Variable not found, keep the original name
                buffer[j++] = '$';
                for (int n = 0; n < k && j < 255; n++) {
                    buffer[j++] = var_name[n];
                }
            }
            if (input[i] != '\0') i--; // Re-adjust for outer loop increment
        } else {
            // Regular character, copy to buffer
            buffer[j++] = input[i];
        }
    }
    buffer[j] = '\0';
    printf("%s\n", buffer);
}

// Function to display user-defined and environment variables separately
void list_vars() {
    printf("User-defined variables:\n");
    for (int i = 0; i < var_count; i++) {
        if (!vars[i].global) {
            printf("  %s=%s\n", vars[i].name, vars[i].value);
        }
    }
    printf("\nEnvironment variables:\n");
    for (int i = 0; i < var_count; i++) {
        if (vars[i].global) {
            printf("  %s=%s\n", vars[i].name, vars[i].value);
        }
    }
}

// Function to export a user-defined variable as an environment variable
void export_var(const char *name) {
    for (int i = 0; i < var_count; i++) {
        if (strcmp(vars[i].name, name) == 0) {
            vars[i].global = 1;
            return;
        }
    }
    // If variable doesn't exist, create it as an environment variable with an empty value
    set_var(name, "", 1);
}

// Function to process a command
void process_command(char *command) {
    if (strncmp(command, "printenc", 8) == 0) {
        printenc();
    } else if (strncmp(command, "eco ", 4) == 0) {
        eco(command + 4);  // Skip "eco " to get the argument part
    } else if (strncmp(command, "set ", 4) == 0) {
        // Parse set command to get variable name and value
        char *name = strtok(command + 4, "=");
        char *value = strtok(NULL, "\0");
        if (name && value) {
            set_var(name, value, 0); // Assuming local by default
        } else {
            printf("Error: Invalid set syntax. Use 'set name=value'.\n");
        }
    } else if (strncmp(command, "export ", 7) == 0) {
        // Export a variable as environment
        char *name = command + 7;
        // Trim whitespace
        while (*name == ' ') name++;
        export_var(name);
    } else if (strncmp(command, "list", 4) == 0) {
        list_vars();
    } else {
        printf("Error: Unknown command '%s'.\n", command);
    }
}

// Main function
int main() {
    char command[256];

    printf("Welcome to the shell! Type 'exit' to quit.\n");
    while (1) {
        printf("> ");
        if (fgets(command, sizeof(command), stdin) == NULL) break;

        // Remove trailing newline character
        command[strcspn(command, "\n")] = '\0';

        if (strcmp(command, "exit") == 0) break;
        process_command(command);
    }

    // Free allocated memory for variable names and values
    for (int i = 0; i < var_count; i++) {
        free(vars[i].name);
        free(vars[i].value);
    }

    printf("Goodbye!\n");
    return 0;
}

