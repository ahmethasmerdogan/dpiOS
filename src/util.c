/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 ahmethasmerdogan
 */
#include "dpios.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void argv_join(const char *const argv[], char *buf, size_t buflen)
{
    size_t n = 0;
    buf[0] = '\0';
    for (int i = 0; argv[i] && n + 1 < buflen; i++) {
        int k = snprintf(buf + n, buflen - n, "%s%s", i ? " " : "", argv[i]);
        if (k < 0)
            break;
        n += (size_t)k;
    }
}

/*
 * Run a command, optionally feeding it stdin and capturing stdout+stderr.
 * Returns the exit status, or -1 if the child could not be started.
 */
int dp_run_feed(const char *const argv[], const char *stdin_data,
                char *out, size_t outlen)
{
    int in_pipe[2] = { -1, -1 };
    int out_pipe[2] = { -1, -1 };

    if (stdin_data && pipe(in_pipe) != 0)
        return -1;
    if (out && outlen && pipe(out_pipe) != 0) {
        if (in_pipe[0] >= 0) { close(in_pipe[0]); close(in_pipe[1]); }
        return -1;
    }

    char cmdline[512];
    argv_join(argv, cmdline, sizeof(cmdline));
    LOGD("exec: %s", cmdline);

    pid_t pid = fork();
    if (pid < 0) {
        LOGE("fork failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        if (in_pipe[0] >= 0) {
            dup2(in_pipe[0], STDIN_FILENO);
            close(in_pipe[0]);
            close(in_pipe[1]);
        }
        if (out_pipe[1] >= 0) {
            dup2(out_pipe[1], STDOUT_FILENO);
            dup2(out_pipe[1], STDERR_FILENO);
            close(out_pipe[0]);
            close(out_pipe[1]);
        } else {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }

    if (in_pipe[0] >= 0)
        close(in_pipe[0]);
    if (out_pipe[1] >= 0)
        close(out_pipe[1]);

    if (stdin_data) {
        size_t left = strlen(stdin_data);
        const char *p = stdin_data;
        /* the child dying mid-write must not take us with it */
        void (*old)(int) = signal(SIGPIPE, SIG_IGN);
        while (left > 0) {
            ssize_t w = write(in_pipe[1], p, left);
            if (w <= 0)
                break;
            p += w;
            left -= (size_t)w;
        }
        signal(SIGPIPE, old);
        close(in_pipe[1]);
    }

    size_t got = 0;
    if (out_pipe[0] >= 0) {
        while (got + 1 < outlen) {
            ssize_t r = read(out_pipe[0], out + got, outlen - got - 1);
            if (r <= 0)
                break;
            got += (size_t)r;
        }
        close(out_pipe[0]);
    }
    if (out && outlen)
        out[got] = '\0';

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;

    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

int dp_run(const char *const argv[])
{
    return dp_run_feed(argv, NULL, NULL, 0);
}

int dp_run_capture(const char *const argv[], char *out, size_t outlen)
{
    return dp_run_feed(argv, NULL, out, outlen);
}
