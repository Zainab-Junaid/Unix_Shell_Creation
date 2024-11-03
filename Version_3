#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pwd.h>
#include <limits.h>
#include <signal.h>

#define MAX_LEN 512
#define MAXARGS 10
#define ARGLEN 30

void sigchld_handler(int signo);
int execute(char* arglist[], char* input_file, char* output_file, int background);
char** tokenize(char* cmdline);
char* read_cmd(char* prompt, FILE* fp);
void handle_pipe(char* cmdline);
void parse_redirects(char* cmdline, char** arglist, char** input_file, char** output_file);

int main() {
    struct sigaction sa;
    sa.sa_handler = sigchld_handler; // Handle child termination
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP; // Restart functions if interrupted and do not count stopped children
    sigaction(SIGCHLD, &sa, NULL);

    char *cmdline;

    while (1) {
        // Generate and display the prompt with current directory and username
        char prompt[100];
        char cwd[PATH_MAX];
        getcwd(cwd, sizeof(cwd)); // Get current working directory
        struct passwd *pw = getpwuid(getuid()); // Get user information
        char *username = pw->pw_name;

        // Create a prompt string
        snprintf(prompt, sizeof(prompt), "PUCITshell: %s@%s$ ", username, cwd);
        
        // Read command line input
        if ((cmdline = read_cmd(prompt, stdin)) == NULL) {
            break; // Exit on EOF (CTRL+D)
        }

        // Handle pipes if present
        handle_pipe(cmdline);

        free(cmdline); // Free command line input
    }

    printf("\nExiting shell.\n");
    return 0;
}

void sigchld_handler(int signo) {
    // Reap dead processes to prevent zombies
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void handle_pipe(char* cmdline) {
    char* cmd1 = strtok(cmdline, "|");
    char* cmd2 = strtok(NULL, "|");

    if (cmd2 != NULL) {
        // Handle the case for two commands connected by a pipe
        int pipefd[2];
        pipe(pipefd); // Create a pipe

        if (fork() == 0) { // Child process for the first command
            dup2(pipefd[1], STDOUT_FILENO); // Redirect stdout to pipe write end
            close(pipefd[0]); // Close unused read end
            char* arglist[MAXARGS + 1] = { NULL };
            char* input_file = NULL;
            char* output_file = NULL;
            parse_redirects(cmd1, arglist, &input_file, &output_file);
            execute(arglist, input_file, output_file, 0);
            exit(0);
        }

        if (fork() == 0) { // Child process for the second command
            dup2(pipefd[0], STDIN_FILENO); // Redirect stdin to pipe read end
            close(pipefd[1]); // Close unused write end
            char* arglist[MAXARGS + 1] = { NULL };
            char* input_file = NULL;
            char* output_file = NULL;
            parse_redirects(cmd2, arglist, &input_file, &output_file);
            execute(arglist, input_file, output_file, 0);
            exit(0);
        }

        close(pipefd[0]); // Close both ends in the parent
        close(pipefd[1]);
        wait(NULL); // Wait for both children
        wait(NULL);
    } else {
        // No pipe, handle normally
        char* arglist[MAXARGS + 1] = { NULL };
        char* input_file = NULL;
        char* output_file = NULL;
        int background = 0; // Background flag

        // Check for background execution
        if (strchr(cmdline, '&') != NULL) {
            background = 1;
            // Remove '&' from the command line
            char* ampersand = strchr(cmdline, '&');
            *ampersand = '\0'; // Null-terminate at '&'
        }

        parse_redirects(cmdline, arglist, &input_file, &output_file);
        execute(arglist, input_file, output_file, background);
    }
}

int execute(char* arglist[], char* input_file, char* output_file, int background) {
    int status;
    pid_t cpid = fork();
    
    if (cpid == -1) {
        perror("fork failed");
        exit(1);
    } else if (cpid == 0) { // Child process
        if (input_file != NULL) {
            int fd_in = open(input_file, O_RDONLY);
            if (fd_in < 0) {
                perror("Input file error");
                exit(1);
            }
            dup2(fd_in, STDIN_FILENO); // Redirect stdin
            close(fd_in);
        }

        if (output_file != NULL) {
            int fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
            if (fd_out < 0) {
                perror("Output file error");
                exit(1);
            }
            dup2(fd_out, STDOUT_FILENO); // Redirect stdout
            close(fd_out);
        }

        execvp(arglist[0], arglist); // Execute the command
        perror("Command not found..."); // If exec fails
        exit(1); // Exit child process if exec fails
    } else { // Parent process
        if (background) {
            printf("[%d] %d\n", getpid(), cpid); // Display PID of background process
            return 0; // Return without waiting
        } else {
            waitpid(cpid, &status, 0); // Wait for child process to finish
            printf("Child exited with status %d\n", status >> 8);
        }
    }
    return 0;
}

void parse_redirects(char* cmdline, char** arglist, char** input_file, char** output_file) {
    char* token = strtok(cmdline, " ");
    int argnum = 0;

    while (token != NULL) {
        if (strcmp(token, "<") == 0) {
            token = strtok(NULL, " "); // Get the next token for the input file
            if (token != NULL) {
                *input_file = token;
            }
        } else if (strcmp(token, ">") == 0) {
            token = strtok(NULL, " "); // Get the next token for the output file
            if (token != NULL) {
                *output_file = token;
            }
        } else {
            arglist[argnum++] = token; // Store the command or argument
        }
        token = strtok(NULL, " ");
    }

    arglist[argnum] = NULL; // Null-terminate the argument list
}

char* read_cmd(char* prompt, FILE* fp) {
    printf("%s", prompt);
    int c; // input character
    int pos = 0; // position of character in cmdline
    char* cmdline = (char*)malloc(sizeof(char) * MAX_LEN);
    
    if (!cmdline) return NULL; // Check allocation success

    while ((c = getc(fp)) != EOF) {
        if (c == '\n') break;
        cmdline[pos++] = c;
    }

    // Check for EOF (CTRL+D)
    if (c == EOF && pos == 0) {
        free(cmdline);
        return NULL;
    }

    cmdline[pos] = '\0';
    return cmdline;
}
