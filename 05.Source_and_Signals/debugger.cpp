#include "pch.h"

#include <stdexcept>

#include "register.h"

namespace {

uint64_t parse_integer(const std::string& text) {
    if (text.empty()) {
        throw std::invalid_argument("missing numeric value");
    }
    std::size_t processed = 0;
    const auto value = std::stoull(text, &processed, 0);
    if (processed != text.size()) {
        throw std::invalid_argument("invalid numeric value: " + text);
    }
    return value;
}

void report_error(const std::string& message) {
    std::cerr << "[!] " << message << '\n';
}

void report_error(const std::exception& ex) {
    report_error(ex.what());
}

} // namespace

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

void debugger::handle_command(const std::string& line) {
    auto args = split(line, ' ');
    if (args.empty()) return;
    const auto& command = args[0];

    if (is_prefix(command, std::string("continue"))) {
        continue_execution();
        return;
    }

    if (command == "break" || command == "b") {
        if (args.size() < 2) {
            report_error("Usage: break <address>");
            return;
        }
        try {
            auto addr = static_cast<std::intptr_t>(parse_integer(args[1]));
            set_breakpoint_at_address(addr);
        } catch (const std::exception& ex) {
            report_error(ex);
        }
        return;
    }

    if (command == "quit" || command == "q") {
        std::cout << "bye\n";
        kill(m_pid, SIGKILL);
        return;
    }

    if (is_prefix(command, "register")) {
        if (args.size() < 2) {
            report_error("Usage: register <dump|read|write> ...");
            return;
        }
        const auto& subcommand = args[1];
        if (is_prefix(subcommand, "dump")) {
            dump_registers();
            return;
        }
        if (is_prefix(subcommand, "read")) {
            if (args.size() < 3) {
                report_error("Usage: register read <name>");
                return;
            }
            try {
                auto value = get_register_value(m_pid, get_register_from_name(args[2]));
                std::cout << args[2] << " = 0x" << std::hex << value << std::dec << '\n';
            } catch (const std::exception& ex) {
                report_error(ex);
            }
            return;
        }
        if (is_prefix(subcommand, "write")) {
            if (args.size() < 4) {
                report_error("Usage: register write <name> <value>");
                return;
            }
            try {
                const auto reg = get_register_from_name(args[2]);
                const auto value = parse_integer(args[3]);
                set_register_value(m_pid, reg, value);
            } catch (const std::exception& ex) {
                report_error(ex);
            }
            return;
        }
        report_error("Unknown register command: " + subcommand);
        return;
    }

    if (is_prefix(command, "memory")) {
        if (args.size() < 2) {
            report_error("Usage: memory <read|write> ...");
            return;
        }
        const auto& subcommand = args[1];
        if (is_prefix(subcommand, "read")) {
            if (args.size() < 3) {
                report_error("Usage: memory read <address>");
                return;
            }
            try {
                const auto address = parse_integer(args[2]);
                const auto value = read_memory(address);
                std::cout << "0x" << std::hex << value << std::dec << '\n';
            } catch (const std::exception& ex) {
                report_error(ex);
            }
            return;
        }
        if (is_prefix(subcommand, "write")) {
            if (args.size() < 4) {
                report_error("Usage: memory write <address> <value>");
                return;
            }
            try {
                const auto address = parse_integer(args[2]);
                const auto value = parse_integer(args[3]);
                write_memory(address, value);
            } catch (const std::exception& ex) {
                report_error(ex);
            }
            return;
        }
        report_error("Unknown memory command: " + subcommand);
        return;
    }

    std::cerr << "Unknown command: " << command << '\n';
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
    step_over_breakpoint();

    if (ptrace(PTRACE_CONT, m_pid, nullptr, nullptr) == -1) {
        perror("ptrace(PTRACE_CONT)");
        return;
    }

    wait_for_signal();
}

void debugger::set_breakpoint_at_address(std::intptr_t addr){
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::dec << '\n';
    breakpoint bp{m_pid, addr};
    bp.enable();
    m_breakpoints.insert_or_assign(addr, std::move(bp));
}

void debugger::dump_registers() {
    std::ios_base::fmtflags original_flags{std::cout.flags()};
    for (const auto& rd : g_register_descriptors) {
        try {
            const auto value = get_register_value(m_pid, rd.r);
            std::cout << rd.name << " 0x" << std::hex << value << std::dec << '\n';
        } catch (const std::exception& ex) {
            report_error(std::string("failed to read register ") + rd.name + ": " + ex.what());
        }
    }
    std::cout.flags(original_flags);
}

uint64_t debugger::read_memory(uint64_t address) {
    errno = 0;
    const auto data = ptrace(PTRACE_PEEKDATA, m_pid, reinterpret_cast<void*>(address), nullptr);
    if (data == -1 && errno) {
        throw std::runtime_error(std::string("ptrace(PTRACE_PEEKDATA) failed: ") + std::strerror(errno));
    }
    return static_cast<uint64_t>(data);
}

void debugger::write_memory(uint64_t address, uint64_t value) {
    errno = 0;
    if (ptrace(PTRACE_POKEDATA, m_pid, reinterpret_cast<void*>(address), reinterpret_cast<void*>(value)) == -1) {
        throw std::runtime_error(std::string("ptrace(PTRACE_POKEDATA) failed: ") + std::strerror(errno));
    }
}

uint64_t debugger::get_pc() const {
    return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) {
    set_register_value(m_pid, reg::rip, pc);
}

void debugger::step_over_breakpoint() {
    const auto possible_breakpoint_location = static_cast<std::intptr_t>(get_pc() - 1);

    const auto it = m_breakpoints.find(possible_breakpoint_location);
    if (it == m_breakpoints.end()) return;

    auto& bp = it->second;
    if (!bp.is_enabled()) return;

    const auto previous_instruction_address = static_cast<uint64_t>(possible_breakpoint_location);
    set_pc(previous_instruction_address);

    bp.disable();
    if (ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr) == -1) {
        perror("ptrace(PTRACE_SINGLESTEP)");
    } else {
        wait_for_signal(false);
    }
    bp.enable();
}

int debugger::wait_for_signal(bool report) {
    int wait_status = 0;

    // auto options = 0;
    // waitpid(m_pid, &wait_status, options);

    // auto siginfo = get_signal_info();

    // switch (siginfo.si_signo) {
    // case SIGTRAP:
    //     handle_sigtrap(siginfo);
    //     break;
    // case SIGSEGV:
    //     std::cout << "Yay, segfault. Reason: " << siginfo.si_code << std::endl;
    //     break;
    // default:
    //     std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    // }

    if (waitpid(m_pid, &wait_status, 0) < 0) {
        perror("waitpid");
        return -1;
    }

    if (report) {
        if (WIFSTOPPED(wait_status)) {
            const auto sig = WSTOPSIG(wait_status);
            std::cout << "[stopped] signal " << sig << '\n';
        } else if (WIFEXITED(wait_status)) {
            std::cout << "[exit] status " << WEXITSTATUS(wait_status) << '\n';
        } else if (WIFSIGNALED(wait_status)) {
            std::cout << "[killed] by signal " << WTERMSIG(wait_status) << '\n';
        }
    }

    return wait_status;
}

dwarf::die debugger::get_function_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            for (const auto& die : cu.root()) {
                if (die.tag == dwarf::DW_TAG::subprogram) {
                    if (die_pc_range(die).contains(pc)) {
                        return die;
                    }
                }
            }
        }
    }
    throw std::out_of_range{"Cannot find function"};
}

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            auto& lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it != lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            }
            else {
                return it;
            }
        }
    }
    throw std::out_of_range{"Cannot find line entry"};
}

void debugger::run(){
    wait_for_signal();
    initialize_load_address();
}

void debugger::initialize_load_address() {
    // If this is a dynamic library (e.g PIE)
    if (m_elf.get_hdr().type == elf::et::dyn){
        // the load address is found in /proc/<pid>/maps
        std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");

        //read the first address from the file
        // ASLR 껐다고 가정하고 있는것으로 보임
        std::string addr;
        std::getline(map, addr, '-');

        m_load_address = std::stol(addr, 0, 16);
    }
}

uint64_t debugger::offset_load_address(uint64_t addr) {
    return addr - m_load_address;
}

void debugger::print_source(const std::string& file_name, unsigned line, unsigned n_lines_context){
    std::ifstream file {file_name};

    //Work out a window around the desired line
    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;

    char c{};
    auto current_line = 1u;
    //skip lines up until start_line
    while (current_line != start_line && file.get(c)){
        if (c == '\n'){
            ++current_line;
        }
    }

    //output cursor if we are at the current line
    std::cout << (current_line == line ? "> " : "  ");

    //write lines up until end_line
    while (current_line <= end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n') {
            ++current_line;
            //output cursor if we are at the current line
            std::cout << (current_line == line ? "> " : "  ");
        }
    }

    // write newline and make sure that the stream is flushed properly
    std::cout << std::endl;
}

siginfo_t debugger::get_signal_info() {
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
    return info;
} 

void debugger::handle_sigtrap(siginfo_t info) {
    switch (info.si_code) {
    //one of these will be set if a breakpoint was hit
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        set_pc(get_pc()-1); //put the pc back where it should be
        std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::endl;
        auto offset_pc = offset_load_address(get_pc()); //rember to offset the pc for querying DWARF
        auto line_entry = get_line_entry_from_pc(offset_pc);
        print_source(line_entry->file->path, line_entry->line);
        return;
    }
    //this will be set if the signal was sent by single stepping
    case TRAP_TRACE:
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
        return;
    }
}

void debugger::step_over_breakpoint() {
    if (m_breakpoints.count(get_pc())) {
        auto& bp = m_breakpoints[get_pc()];
        if (bp.is_enabled()) {
            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}