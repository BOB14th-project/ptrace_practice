#include "pch.h"

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
    } else if (command == "break" || command == "b") {
        if (args.size() < 2) {
            std::cerr << "Usage: break <address>\n";
            return;
        }
        std::intptr_t addr = std::stol(args[1], 0, 16);
        set_breakpoint_at_address(addr);
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

void debugger::set_breakpoint_at_address(std::intptr_t addr){
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::dec << '\n';
    breakpoint bp{m_pid, addr};
    bp.enable();
    m_breakpoints.insert_or_assign(addr, std::move(bp));
}
