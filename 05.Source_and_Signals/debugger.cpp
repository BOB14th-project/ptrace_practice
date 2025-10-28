#include "pch.h"

#include <stdexcept>
#include <fstream>

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
    const auto wait_status = wait_for_signal(false);
    if (wait_status == -1) {
        return;
    }

    if (WIFEXITED(wait_status)) {
        std::cerr << "[!] Process exited before we could attach (status=" << WEXITSTATUS(wait_status) << ")\n";
        return;
    }

    if (WIFSIGNALED(wait_status)) {
        std::cerr << "[!] Process received signal " << WTERMSIG(wait_status) << " before we could attach\n";
        return;
    }

    initialize_load_address();

    long r = ptrace(PTRACE_SETOPTIONS, m_pid, 0,
                    PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
    if (r == -1) {
        perror("ptrace(PTRACE_SETOPTIONS)");
    }

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

int debugger::wait_for_signal(bool report) {
    int wait_status = 0;
    if (waitpid(m_pid, &wait_status, 0) < 0) {
        perror("waitpid");
        return -1;
    }

    if (WIFEXITED(wait_status)) {
        if (report) {
            std::cout << "[exit] status " << WEXITSTATUS(wait_status) << '\n';
        }
        return wait_status;
    }

    if (WIFSIGNALED(wait_status)) {
        if (report) {
            std::cout << "[killed] by signal " << WTERMSIG(wait_status) << '\n';
        }
        return wait_status;
    }

    if (WIFSTOPPED(wait_status)) {
        const auto sig = WSTOPSIG(wait_status);
        const auto info = get_signal_info();

        switch (sig) {
        case SIGTRAP:
            handle_sigtrap(info);
            break;
        case SIGSEGV:
            if (report) {
                std::cout << "Received SIGSEGV (code " << info.si_code
                          << ") at address 0x" << std::hex
                          << reinterpret_cast<std::uintptr_t>(info.si_addr)
                          << std::dec << '\n';
            }
            break;
        default:
            if (report) {
                std::cout << "Stopped by signal " << strsignal(sig) << '\n';
            }
            break;
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
            if (it == lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            }
            return it;
        }
    }
    throw std::out_of_range{"Cannot find line entry"};
}

void debugger::initialize_load_address() {
    m_load_address = 0;

    if (m_elf.get_hdr().type != elf::et::dyn) {
        return;
    }

    std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");
    if (!map) {
        report_error("failed to open /proc/" + std::to_string(m_pid) + "/maps");
        return;
    }

    std::string addr;
    if (std::getline(map, addr, '-')) {
        try {
            m_load_address = std::stoull(addr, nullptr, 16);
        } catch (const std::exception& ex) {
            report_error(std::string("failed to parse load address: ") + ex.what());
        }
    } else {
        report_error("unexpected format while reading load address");
    }
}

uint64_t debugger::offset_load_address(uint64_t addr) const {
    if (m_load_address == 0 || addr < m_load_address) {
        return addr;
    }
    return addr - m_load_address;
}

void debugger::print_source(const std::string& file_name, unsigned line, unsigned n_lines_context){
    std::ifstream file{file_name};
    if (!file) {
        report_error("failed to open source file: " + file_name);
        return;
    }

    // Work out a window around the desired line
    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;

    char c{};
    auto current_line = 1u;
    // Skip lines up until start_line
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') {
            ++current_line;
        }
    }

    if (current_line > end_line) {
        return;
    }

    std::cout << (current_line == line ? "> " : "  ");

    // Write lines up until end_line
    while (current_line <= end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n') {
            ++current_line;
            // Output cursor if we are at the current line
            std::cout << (current_line == line ? "> " : "  ");
        }
    }

    std::cout << std::endl;
}

siginfo_t debugger::get_signal_info() {
    siginfo_t info{};
    if (ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info) == -1) {
        perror("ptrace(PTRACE_GETSIGINFO)");
        std::memset(&info, 0, sizeof(info));
    }
    return info;
}

void debugger::handle_sigtrap(siginfo_t info) {
    switch (info.si_code) {
    //one of these will be set if a breakpoint was hit
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        const auto pc = get_pc() - 1;
        set_pc(pc); // put the pc back where it should be
        std::cout << "Hit breakpoint at address 0x" << std::hex << pc << std::dec << '\n';

        const auto offset_pc = offset_load_address(pc);
        try {
            auto line_entry = get_line_entry_from_pc(offset_pc);
            print_source(line_entry->file->path, line_entry->line, 2);
        } catch (const std::exception& ex) {
            report_error(std::string("failed to print source: ") + ex.what());
        }
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
    const auto it = m_breakpoints.find(get_pc());
    if (it == m_breakpoints.end()) {
        return;
    }

    auto& bp = it->second;
    if (!bp.is_enabled()) {
        return;
    }

    bp.disable();
    if (ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr) == -1) {
        perror("ptrace(PTRACE_SINGLESTEP)");
    } else {
        wait_for_signal(false);
    }
    bp.enable();
}
