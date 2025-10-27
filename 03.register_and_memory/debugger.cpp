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
    } else if (is_prefix(command, "register")){
        if (is_prefix(args[1], "dump")) {
            dump_registers();
        } else if (is_prefix(args[1], "read")) {
            std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
        } else if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2}; // assume 0xVAL
            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
        }
    } else if (is_prefix(command, "memory")) {
        std::string addr{args[2], 2}; // assume 0xADDR

        if(is_prefix(args[1], "read")){
            std::cout << std::hex << read_memory(std::stol(addr,0,16)) << std::endl; 
        }
        else if(is_prefix(args[1], "write")){
            std::string val {args[3], 2}; // assume 0xVAL
            write_memory(std::stol(addr,0,16), std::stol(val,0,16));
        }
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

void debugger::dump_registers(){
    for(const auto& rd : g_register_descriptors){
        uint64_t value = get_register_value(m_pid, rd.r);
        std::cout << rd.name << " 0x" << std::hex << value << std::dec << '\n';
    }
}

uint64_t debugger::read_memory(uint64_t address){
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value){
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

uint64_t debugger::get_pc(){
    return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc){
    set_register_value(m_pid, reg::rip, pc);
}

void debugger::step_over_breakpoint(){
    // -1 because execution will go past the breakpoint
    auto possible_breakpoint_location = get_pc() - 1;

    if(m_breakpoints.count(possible_breakpoint_location)){
        auto& bp = m_breakpoints[possible_breakpoint_location];

        if (bp.is_enabled()){
            auto previous_instruction_address = possible_breakpoint_location;
            set_pc(previous_instruction_address);

            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}

void debugger::wait_for_signal(){
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
}

void debugger::continue_execution(){
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}