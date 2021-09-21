// should link with -rdynamic -ldl
//
// stack layout:
//
// +---------+------------------+
// | EBP - 4 | local variables  |
// | EBP     | callees EBP      |
// | EBP + 4 | ret-addr         |
// | EBP + 8 | parameters       |
// +---------+------------------+
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <execinfo.h>
#ifndef NO_CXXABI
#include <cxxabi.h>
#endif

#define VIOLATE_MAX_FRAMES 16
#define VIOLATAE_INFO_MAX  8192

static void* violate_address = NULL;
static void* violate_bt[VIOLATE_MAX_FRAMES];
static int   violate_frames = 0;
char  violate_info[VIOLATAE_INFO_MAX] = {0};

void segv_handler(int signo, siginfo_t *si, void *ptr)
{
    char** stack_strings;
    int offset = 0;
    ucontext_t* ucontext = (ucontext_t*)ptr;
    int i;
    int f = 0;
    Dl_info dlinfo;
    void** bp = NULL;
    void* ip = NULL;

    if (signo == SIGSEGV) {
        violate_address = si->si_addr;
        offset += sprintf(violate_info + offset, "signal: %d\n", signo);
        offset += sprintf(violate_info + offset, "errno : %d\n", si->si_errno);
        offset += sprintf(violate_info + offset, "code  : %d\n", si->si_code);
        offset += sprintf(violate_info + offset, "  code maps(signal SIGSEGV):\n");
        offset += sprintf(violate_info + offset, "    %d -> SEGV_MAPERR\n", SEGV_MAPERR);
        offset += sprintf(violate_info + offset, "    %d -> SEGV_ACCERR\n", SEGV_ACCERR);
        offset += sprintf(violate_info + offset, "violate_address: %p\n", violate_address);

        offset += sprintf(violate_info + offset, "Registers:\n");
        for (i=0; i<NGREG; i++) {
            offset += sprintf(violate_info + offset,
                    "  reg[%02d]=%p\n", i, ucontext->uc_mcontext.gregs[i]);
        }

#if defined(SIGSEGV_STACK_IA64) || defined(SIGSEGV_STACK_X86)
#if defined(SIGSEGV_STACK_IA64)
        ip = (void*)ucontext->uc_mcontext.gregs[REG_RIP];
        bp = (void**)ucontext->uc_mcontext.gregs[REG_RBP];
#elif defined(SIGSEGV_STACK_X86)
        ip = (void*)ucontext->uc_mcontext.gregs[REG_EIP];
        bp = (void**)ucontext->uc_mcontext.gregs[REG_EBP];
#endif

        offset += sprintf(violate_info + offset, "  IP: %p\n", ip);
        offset += sprintf(violate_info + offset, "  BP: %p\n", bp);

        offset += sprintf(violate_info + offset, "Backtrace(1):\n");
        while(bp && ip) {
            if(!dladdr(ip, &dlinfo))
                break;

            const char *symname = dlinfo.dli_sname;

#ifndef NO_CXXABI
            int status;
            char * demangle_symname = __cxxabiv1::__cxa_demangle(symname, NULL, 0, &status);

            offset += sprintf(violate_info + offset, "  %2d: %p %s(%s+%lu[%s])\n",
                    ++f,
                    ip,
                    dlinfo.dli_fname,
                    symname,
                    (unsigned long)ip - (unsigned long)dlinfo.dli_saddr,
                    (demangle_symname ? demangle_symname : symname));

            if (demangle_symname)
                free(demangle_symname);

#else
            offset += sprintf(violate_info + offset, "  %2d %p %s(%s+%lu)\n",
                    ++f,
                    ip,
                    dlinfo.dli_fname,
                    symname,
                    (unsigned long)ip - (unsigned long)dlinfo.dli_saddr);
#endif

            if(dlinfo.dli_sname && !strcmp(dlinfo.dli_sname, "main"))
                break;

            ip = bp[1];
            bp = (void**)bp[0];
        }
#else
        offset += sprintf(violate_info + offset, "Backtrace(2):\n");
        violate_frames = backtrace(violate_bt, VIOLATE_MAX_FRAMES);
        backtrace_symbols(violate_bt, violate_frames);

        stack_strings = backtrace_symbols(violate_bt, violate_frames);
        for (i=0; i<violate_frames; ++i) {
            offset += sprintf(violate_info + offset, "  %s\n", stack_strings[i]);
        }
#endif

        char ofile[PATH_MAX] = {0};
        sprintf(ofile, "report.%d.txt", getpid());
        int fd = open(ofile, O_WRONLY | O_CREAT, 0644);
        if (fd != -1) {
            write(fd, violate_info, offset);
            close(fd);
        }


        printf("%s\n", violate_info);

        kill(getpid(), SIGILL);
    }
}


void install_segv_handler()
{
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        perror("sigaction");

}

