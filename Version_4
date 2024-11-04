#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#define HISTORY_SIZE 10

void sigchld_handler(int signo);
int execute(char* arglist[], char* input_file, char* output_file, int background);
char** tokenize(char* cmdline);
char* read_cmd(char* prompt, FILE* fp);
void handle_pipe(char* cmdline);
void parse_redirects(char* cmdline, char** arglist, char** input_file, char** output_file);

char* history[HISTORY_SIZE]; // History buffer
int history_index = 0;       // Index for circular history buffer
int history_count = 0;       // Total number of commands in history

void add_to_history(char* cmd) {
    if (history[history_index]) {
        free(history[history_index]); // Free the oldest command in circular buffer
    }
    history[history_index] = strdup(cmd); // Add new command to history
    history_index = (history_index + 1) % HISTORY_SIZE; // Move index
    if (history_count < HISTORY_SIZE) history_count++; // Track up to HISTORY_SIZE
}

char* get_history_command(int index) {
    if (index == -1) {
        index = history_count - 1; // Get last command
    } else {
        index--; // Convert 1-based to 0-based
    }
    
    if (index < 0 || index >= history_count) {
        return NULL; // Invalid command number
    }
    
    // Return a copy of the command to safely manage memory
    return strdup(history[(history_index + HISTORY_SIZE - history_count + index) % HISTORY_SIZE]);
}

int main() {
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    char *cmdline;

    while (1) {
        char prompt[100];
        char cwd[PATH_MAX];
        getcwd(cwd, sizeof(cwd));
        struct passwd *pw = getpwuid(getuid());
        char *username = pw->pw_name;
        snprintf(prompt, sizeof(prompt), "PUCITshell: %s@%s$ ", username, cwd);

        cmdline = read_cmd(prompt, stdin);

        if (cmdline == NULL) {
            break;
        }

        if (cmdline[0] == '!') {
            int cmd_num = atoi(cmdline + 1);
            free(cmdline); // Free original cmdline to prevent memory leak
            cmdline = get_history_command(cmd_num);

            if (cmdline == NULL) {
                printf("No command found in history.\n");
                continue;
            }
            printf("Repeating command: %s\n", cmdline);
        } else {
            add_to_history(cmdline);
        }

        handle_pipe(cmdline);
        free(cmdline); // Free after processing
    }

    printf("\nExiting shell.\n");
    return 0;
}

void sigchld_handler(int signo) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void handle_pipe(char* cmdline) {
    char* cmd1 = strtok(cmdline, "|");
    char* cmd2 = strtok(NULL, "|");

    if (cmd2 != NULL) {
        int pipefd[2];
        pipe(pipefd);

        if (fork() == 0) {
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[0]);
            char* arglist[MAXARGS + 1] = { NULL };
            char* input_file = NULL;
            char* output_file = NULL;
            parse_redirects(cmd1, arglist, &input_file, &output_file);
            execute(arglist, input_file, output_file, 0);
            exit(0);
        }

        if (fork() == 0) {
            dup2(pipefd[0], STDIN_FILENO);
            close(pipefd[1]);
            char* arglist[MAXARGS + 1] = { NULL };
            char* input_file = NULL;
            char* output_file = NULL;
            parse_redirects(cmd2, arglist, &input_file, &output_file);
            execute(arglist, input_file, output_file, 0);
            exit(0);
        }

        close(pipefd[0]);
        close(pipefd[1]);
        wait(NULL);
        wait(NULL);
    } else {
        char* arglist[MAXARGS + 1] = { NULL };
        char* input_file = NULL;
        char* output_file = NULL;
        int background = 0;

        if (strchr(cmdline, '&') != NULL) {
            background = 1;
            char* ampersand = strchr(cmdline, '&');
            *ampersand = '\0';
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
    } else if (cpid == 0) {
        if (input_file != NULL) {
            int fd_in = open(input_file, O_RDONLY);
            if (fd_in < 0) {
                perror("Input file error");
                exit(1);
            }
            dup2(fd_in, STDIN_FILENO);
            close(fd_in);
        }

        if (output_file != NULL) {
            int fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
            if (fd_out < 0) {
                perror("Output file error");
                exit(1);
            }
            dup2(fd_out, STDOUT_FILENO);
            close(fd_out);
        }

        execvp(arglist[0], arglist);
        perror("Command not found...");
        exit(1);
    } else {
        if (background) {
            printf("[%d] %d\n", getpid(), cpid);
            return 0;
        } else {
            waitpid(cpid, &status, 0);
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
            token = strtok(NULL, " ");
            if (token != NULL) {
                *input_file = token;
            }
        } else if (strcmp(token, ">") == 0) {
            token = strtok(NULL, " ");
            if (token != NULL) {
                *output_file = token;
            }
        } else {
            arglist[argnum++] = token;
        }
        token = strtok(NULL, " ");
    }

    arglist[argnum] = NULL;
}

char* read_cmd(char* prompt, FILE* fp) {
    printf("%s", prompt);
    int c;
    int pos = 0;
    char* cmdline = (char*)malloc(sizeof(char) * MAX_LEN);
    if (!cmdline) return NULL;

    while ((c = getc(fp)) != EOF) {
        if (c == '\n') break;
        cmdline[pos++] = c;
    }

    if (c == EOF && pos == 0) {
        free(cmdline);
        return NULL;
    }

    cmdline[pos] = '\0';
    return cmdline;
}
