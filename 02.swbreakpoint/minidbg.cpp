#include "pch.h"

static inline long read_word(pid_t pid, std::intptr_t addr){
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, pid, reinterpret_cast<void*>(addr), nullptr);
    if (data == -1 && errno){
        perror("ptrace(PEEKDATA)");
    }
    return data;
}
static inline void write_word(pid_t pid, std::intptr_t addr, long data){
    if (ptrace(PTRACE_POKEDATA, pid, reinterpret_cast<void*>(addr), reinterpret_cast<void*>(data)) == -1){
        perror("ptrace(POKEDATA)");
    }
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <program-to-debug> [args...]\n";
        return 1;
    }

    const char *prog = argv[1];

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // Child: become tracee and exec the target
        if (personality(ADDR_NO_RANDOMIZE) == -1) {
            perror("personality(ADDR_NO_RANDOMIZE)");
            _exit(1);
        }
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            perror("ptrace(PTRACE_TRACEME)");
            _exit(1);
        }
        // Ensure the child stops so the parent can set options after exec
        // The exec* below will deliver SIGTRAP to the parent (post-exec-stop)

        // Build argv for execvp: reuse current argv from argv[1] onward
        std::vector<char *> child_argv;
        child_argv.reserve(argc); // rough
        for (int i = 1; i < argc; ++i) child_argv.push_back(argv[i]);
        child_argv.push_back(nullptr);

        execvp(prog, child_argv.data());
        perror("execvp");
        _exit(1);
    }

    // Parent: run the debugger loop
    debugger dbg{prog, pid};
    dbg.run();

    return 0;
}
