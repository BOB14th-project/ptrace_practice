#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Using std::getline for a simple REPL; no external linenoise dependency.

class debugger {
public:
    debugger(std::string prog_name, pid_t pid)
        : m_prog_name{std::move(prog_name)}, m_pid{pid} {}

    void run();

private:
    void handle_command(const std::string &line);
    void continue_execution();

    static std::vector<std::string> split(const std::string &s, char delimiter);
    static bool is_prefix(const std::string &s, const std::string &of);

private:
    std::string m_prog_name;
    pid_t m_pid;
};

void debugger::run() {
    // Wait for the child to stop on its initial SIGTRAP after execve
    int wait_status = 0;
    if (waitpid(m_pid, &wait_status, 0) < 0) {
        perror("waitpid (initial)");
        return;
    }

    if (WIFEXITED(wait_status)) {
        std::cerr << "[!] Process exited before we could attach (status=" << WEXITSTATUS(wait_status) << ")\n";
        return;
    }

    // Set a couple of helpful ptrace options early
    long r = ptrace(PTRACE_SETOPTIONS, m_pid, 0,
                    PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
    if (r == -1) {
        perror("ptrace(PTRACE_SETOPTIONS)");
    }

    // Simple REPL using std::getline (portable, no extra dependency)
    for (std::string cmdline; std::cout << "minidbg> " && std::getline(std::cin, cmdline);) {
        if (!cmdline.empty()) handle_command(cmdline);
    }
}

void debugger::handle_command(const std::string &line) {
    auto args = split(line, ' ');
    if (args.empty()) return;

    const auto &command = args[0];

    if (is_prefix(command, std::string("continue"))) {
        continue_execution();
    } else if (command == "quit" || command == "q") {
        std::cout << "bye\n";
        // Let the loop in run() end by simulating EOF on stdin if needed.
        // Here we simply send SIGKILL to the child and return; real dbg would detach.
        kill(m_pid, SIGKILL);
        // nothing else to do; user can Ctrl+D to exit the REPL
    } else {
        std::cerr << "Unknown command: " << command << "\n";
    }
}

std::vector<std::string> debugger::split(const std::string &s, char delimiter) {
    std::vector<std::string> out{};
    std::stringstream ss{s};
    std::string item;

    while (std::getline(ss, item, delimiter)) {
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

bool debugger::is_prefix(const std::string &s, const std::string &of) {
    // Returns true if s is a prefix of of, so "cont" matches "continue"
    if (s.size() > of.size()) return false;
    return std::equal(s.begin(), s.end(), of.begin());
}

void debugger::continue_execution() {
    if (ptrace(PTRACE_CONT, m_pid, nullptr, nullptr) == -1) {
        perror("ptrace(PTRACE_CONT)");
        return;
    }

    int wait_status = 0;
    if (waitpid(m_pid, &wait_status, 0) < 0) {
        perror("waitpid (continue)");
        return;
    }

    if (WIFSTOPPED(wait_status)) {
        int sig = WSTOPSIG(wait_status);
        std::cout << "[stopped] signal " << sig << "\n";
    } else if (WIFEXITED(wait_status)) {
        std::cout << "[exit] status " << WEXITSTATUS(wait_status) << "\n";
    } else if (WIFSIGNALED(wait_status)) {
        std::cout << "[killed] by signal " << WTERMSIG(wait_status) << "\n";
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
