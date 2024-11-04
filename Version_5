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

typedef struct {
    pid_t pid;
    char command[MAX_LEN];
} bg_process;

bg_process bg_processes[MAXARGS];
int bg_process_count = 0;

void sigchld_handler(int signo);
int execute(char* arglist[], char* input_file, char* output_file, int background);
int handle_builtin(char* arglist[]);
void list_bg_processes();
void remove_bg_process(pid_t pid);
char** tokenize(char* cmdline);
char* read_cmd(char* prompt, FILE* fp);
void handle_pipe(char* cmdline);
void parse_redirects(char* cmdline, char** arglist, char** input_file, char** output_file);

int main() {
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    char* cmdline;

    while (1) {
        char prompt[100];
        char cwd[PATH_MAX];
        getcwd(cwd, sizeof(cwd));
        struct passwd* pw = getpwuid(getuid());
        char* username = pw->pw_name;

        snprintf(prompt, sizeof(prompt), "PUCITshell: %s@%s$ ", username, cwd);

        if ((cmdline = read_cmd(prompt, stdin)) == NULL) {
            break;
        }

        handle_pipe(cmdline);
        free(cmdline);
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
        if (!handle_builtin(arglist)) {
            execute(arglist, input_file, output_file, background);
        }
    }
}

int handle_builtin(char* arglist[]) {
    if (strcmp(arglist[0], "cd") == 0) {
        if (arglist[1]) {
            if (chdir(arglist[1]) != 0) {
                perror("cd failed");
            }
        } else {
            printf("cd: missing argument\n");
        }
        return 1;
    } else if (strcmp(arglist[0], "exit") == 0) {
        exit(0);
    } else if (strcmp(arglist[0], "jobs") == 0) {
        list_bg_processes();
        return 1;
    } else if (strcmp(arglist[0], "kill") == 0) {
        if (arglist[1]) {
            int job_num = atoi(arglist[1]) - 1;
            if (job_num >= 0 && job_num < bg_process_count) {
                kill(bg_processes[job_num].pid, SIGKILL);
                remove_bg_process(bg_processes[job_num].pid);
            } else {
                printf("Invalid job number.\n");
            }
        } else {
            printf("kill: missing argument\n");
        }
        return 1;
    } else if (strcmp(arglist[0], "help") == 0) {
        printf("Available built-in commands:\n");
        printf("cd <path>    - Change directory to <path>\n");
        printf("exit         - Exit the shell\n");
        printf("jobs         - List background jobs\n");
        printf("kill <num>   - Kill the job number <num>\n");
        printf("help         - Display this help message\n");
        return 1;
    }
    return 0;
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
            int fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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
            bg_processes[bg_process_count].pid = cpid;
            strncpy(bg_processes[bg_process_count++].command, arglist[0], MAX_LEN);
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

void list_bg_processes() {
    for (int i = 0; i < bg_process_count; i++) {
        printf("[%d] %s\n", i + 1, bg_processes[i].command);
    }
}

void remove_bg_process(pid_t pid) {
    int i;
    for (i = 0; i < bg_process_count; i++) {
        if (bg_processes[i].pid == pid) {
            break;
        }
    }
    for (; i < bg_process_count - 1; i++) {
        bg_processes[i] = bg_processes[i + 1];
    }
    bg_process_count--;
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

