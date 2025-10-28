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

uint64_t die_attribute_as_address(const dwarf::die& die, dwarf::DW_AT attr) {
    const auto value = die[attr];
    if (!value) {
        throw std::out_of_range{"missing DWARF attribute"};
    }

    using dwarf::value;
    switch (value.get_type()) {
    case value::type::address:
        return value.as_address();
    case value::type::constant:
        return value.as_uconstant();
    default:
        throw std::runtime_error{"unsupported DWARF attribute encoding"};
    }
}

uint64_t at_low_pc(const dwarf::die& die) {
    return die_attribute_as_address(die, dwarf::DW_AT::low_pc);
}

uint64_t at_high_pc(const dwarf::die& die) {
    const auto attr = die[dwarf::DW_AT::high_pc];
    if (!attr) {
        throw std::out_of_range{"missing high_pc attribute"};
    }

    using dwarf::value;
    switch (attr.get_type()) {
    case value::type::address:
        return attr.as_address();
    case value::type::constant:
        return at_low_pc(die) + attr.as_uconstant();
    default:
        throw std::runtime_error{"unsupported high_pc encoding"};
    }
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

    if (is_prefix(command, "stepi")){
        single_step_instruction_with_breakpoint_check();
        try {
            auto line_entry = get_line_entry_from_pc(get_offset_pc());
            print_source(line_entry->file->path, line_entry->line, 2);
        } catch (const std::exception& ex) {
            report_error(std::string("failed to locate source after stepi: ") + ex.what());
        }
        return;
    }

    if (is_prefix(command, "step")) {
        step_in();
        return;
    }
    if (is_prefix(command, "next")) {
        step_over();
        return;
    }
    if (is_prefix(command, "finish")) {
        step_out();;
        return;
    }

    if (is_prefix(command, "break")){
        if (args[1][0] == '0' && args[1][1] == 'x') {
            std::string addr {args[1], 2};
            set_breakpoint_at_address(std::stol(addr, 0, 16));
        }
        else if (args[1].find(':') != std::string::npos) {
            auto file_and_line = split(args[1], ':');
            set_breakpoint_at_source_line(file_and_line[0], std::stoi(file_and_line[1]));
        }
        else {
            set_breakpoint_at_function(args[1]);
        }
        return;
    }

    if (is_prefix(command, "symbol")){
        auto syms = lookup_symbol(args[1]);
        for (auto&& s : syms) {
            std::cout << s.name << ' ' << to_string(s.type) << " 0x"
                      << std::hex << s.addr << std::dec << std::endl;
        }
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

uint64_t debugger::get_offset_pc() const {
    return offset_load_address(get_pc());
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

void debugger::single_step_instruction(){
    if (ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr) == -1) {
        perror("ptrace(PTRACE_SINGLESTEP)");
        return;
    }
    wait_for_signal();
}

void debugger::single_step_instruction_with_breakpoint_check(){
    // first, check to see if we need to disable and enable a breakpoint
    if(m_breakpoints.count(get_pc())){
        step_over_breakpoint();
    } else {
        single_step_instruction();
    }
}

void debugger::step_out(){
    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer + 8); // return address is 8

    bool should_remove_breakpoint = false;
    if(!m_breakpoints.count(return_address)){
        set_breakpoint_at_address(return_address);
        should_remove_breakpoint = true;
    }

    continue_execution();

    if(should_remove_breakpoint){
        remove_breakpoint(return_address);
    }
}

void debugger::remove_breakpoint(std::intptr_t addr){
    const auto it = m_breakpoints.find(addr);
    if (it == m_breakpoints.end()) {
        return;
    }
    if (it->second.is_enabled()) {
        it->second.disable();
    }
    m_breakpoints.erase(it);
}

void debugger::step_in(){
    unsigned current_line = 0;
    try {
        current_line = get_line_entry_from_pc(get_offset_pc())->line;
    } catch (const std::exception& ex) {
        report_error(std::string("step: cannot resolve current line: ") + ex.what());
        single_step_instruction_with_breakpoint_check();
        return;
    }

    try {
        while (get_line_entry_from_pc(get_offset_pc())->line == current_line) {
            single_step_instruction_with_breakpoint_check();
        }
    } catch (const std::exception&) {
        // Reached code without line info; fall through and try to display whatever we can.
    }

    try {
        auto line_entry = get_line_entry_from_pc(get_offset_pc());
        print_source(line_entry->file->path, line_entry->line, 2);
    } catch (const std::exception& ex) {
        report_error(std::string("step: cannot display source: ") + ex.what());
    }
}

uint64_t debugger::offset_dwarf_address(uint64_t addr) const {
    return addr + m_load_address;
}

void debugger::step_over(){
    dwarf::die func;
    const auto offset_pc = get_offset_pc();

    try {
        func = get_function_from_pc(offset_pc);
    } catch (const std::exception& ex) {
        report_error(std::string("next: cannot identify current function: ") + ex.what());
        single_step_instruction_with_breakpoint_check();
        return;
    }

    const auto func_entry = at_low_pc(func);
    const auto func_end = at_high_pc(func);

    uint64_t start_address = 0;
    try {
        start_address = get_line_entry_from_pc(offset_pc)->address;
    } catch (const std::exception& ex) {
        report_error(std::string("next: cannot resolve current line: ") + ex.what());
    }

    std::vector<std::intptr_t> to_delete{};

    for (auto& cu : m_dwarf.compilation_units()) {
        if (!die_pc_range(cu.root()).contains(func_entry)) {
            continue;
        }

        auto& lt = cu.get_line_table();
        for (auto it = lt.begin(); it != lt.end(); ++it) {
            if (it->end_sequence) continue;
            if (it->address < func_entry || it->address >= func_end) continue;

            const auto load_address = offset_dwarf_address(it->address);
            if (it->address != start_address && !m_breakpoints.count(load_address)) {
                set_breakpoint_at_address(load_address);
                to_delete.push_back(load_address);
            }
        }
        break;
    }

    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer + 8); // return address is 8
    if(!m_breakpoints.count(return_address)){
        set_breakpoint_at_address(return_address);
        to_delete.push_back(return_address);
    }

    continue_execution();

    for(auto addr : to_delete){
        remove_breakpoint(addr);
    }
}

void debugger::set_breakpoint_at_function(const std::string& name) {
    for (const auto& cu : m_dwarf.compilation_units()) {
        for (const auto& die : cu.root()) {
            if (die.has(dwarf::DW_AT::name) && at_name(die) == name) {
                auto low_pc = at_low_pc(die);
                auto entry = get_line_entry_from_pc(low_pc);
                ++entry; //skip prologue
                set_breakpoint_at_address(offset_dwarf_address(entry->address));
            }
        }
    }
}

void debugger::set_breakpoint_at_source_line(const std::string& file, unsigned line) {
    for (const auto& cu : m_dwarf.compilation_units()) {
        if (is_suffix(file, at_name(cu.root()))) {
            const auto& lt = cu.get_line_table();

            for (const auto& entry : lt) {
                if (entry.is_stmt && entry.line == line) {
                    set_breakpoint_at_address(offset_dwarf_address(entry.address));
                    return;
                }
            }
        }
    }
}

std::vector<symbol> debugger::lookup_symbol(const std::string& name) {
    std::vector<symbol> syms;

    for (auto &sec : m_elf.sections()) {
        if (sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym)
            continue;

        for (auto sym : sec.as_symtab()) {
            if (sym.get_name() == name) {
                auto &d = sym.get_data();
                syms.push_back(symbol{to_symbol_type(d.type()), sym.get_name(), d.value});
            }
        }
    }

    return syms;
}