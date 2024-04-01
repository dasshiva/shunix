/* This code is derived from minimal_strace.c from https://github.com/skeeto/ptrace-examples/blob/master/minimal_strace.c */
#define _POSIX_C_SOURCE 200112L

/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <elf.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <signal.h>

#define FATAL(...) \
    do { \
        fprintf(stderr, "strace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

struct sys_call {
	long syscall;
	long args[6];
};

void handle_syscall(struct sys_call* s) {
	switch (s->syscall) {
		case SYS_exit: exit(0); break;
	        case -1: printf("Hello World"); break;
		default: printf("Unimplented system call = %ld\n", s->syscall); exit(1);
	}
}

int
main(int argc, char **argv)
{
    if (argc <= 1)
        FATAL("too few arguments: %d", argc);

    pid_t pid = fork();
    switch (pid) {
        case -1: /* error */
            FATAL("%s", strerror(errno));
        case 0:  /* child */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            /* Because we're now a tracee, execvp will block until the parent
             * attaches and allows us to continue. */
            execvp(argv[1], argv + 1);
            FATAL("%s", strerror(errno));
    }

    /* parent */
    waitpid(pid, 0, 0); // sync with execvp
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    for (;;) {
	struct sys_call sys;
        /* Enter next system call */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Gather system call arguments */
        struct user_regs_struct regs;
	struct iovec iov;
	iov.iov_base = &regs;
	iov.iov_len = sizeof(struct user_regs_struct);
        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1)
            FATAL("%s", strerror(errno));

#ifdef __aarch64__
        sys.syscall = regs.regs[8];
	memcpy(sys.args, regs.regs, 6);

        /*fprintf(stderr, "%ld(%ld, %ld, %ld, %ld, %ld, %ld)",
                syscall,
                (long)regs.regs[0], (long)regs.regs[1], (long)regs.regs[2],
                (long)regs.regs[3], (long)regs.regs[4],  (long)regs.regs[5]);  */
	regs.regs[8] = 1000;
	ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);

        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Get system call result */
        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
            fputs(" = ?\n", stderr);
            if (errno == ESRCH)
                exit(regs.regs[0]); // system call was _exit(2) or similar
            FATAL("%s", strerror(errno));
        } 

        /* Print system call result */
        //fprintf(stderr, " = %ld\n", (long)regs.regs[0]);
#else
	sys.syscall = regs.orig_rax;
	/* As x86 has named registers we can no longer use memcpy() like above */

	sys.args[0] = regs.rdi;
	sys.args[1] = regs.rsi;
	sys.args[2] = regs.rdx;
	sys.args[3] = regs.r10;
	sys.args[4] = regs.r8;
	sys.args[5] = regs.r9;

        /*fprintf(stderr, "%ld(%ld, %ld, %ld, %ld, %ld, %ld)",
                syscall,
                (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                (long)regs.r10, (long)regs.r8,  (long)regs.r9); */

	regs.orig_rax = 1000;
	ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);

        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Get system call result */
        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
            fputs(" = ?\n", stderr);
            if (errno == ESRCH) {
                exit(regs.rdi); // system call was _exit(2) or similar
	    }
	   FATAL("%s", strerror(errno));
        }
        /* Print system call result */
        //fprintf(stderr, " = %ld\n", (long)regs.rax);
#endif
	handle_syscall(&sys);
    }
}
