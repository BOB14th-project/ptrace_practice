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

bool is_suffix(const std::string& suffix, const std::string& full) {
    if (suffix.size() > full.size()) {
        return false;
    }
    return std::equal(suffix.rbegin(), suffix.rend(), full.rbegin());
}

uint64_t die_attribute_as_address(const dwarf::die& die, dwarf::DW_AT attr) {
    const auto value = die[attr];
    if (!value.valid()) {
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

uint64_t die_low_pc(const dwarf::die& die) {
    return die_attribute_as_address(die, dwarf::DW_AT::low_pc);
}

uint64_t die_high_pc(const dwarf::die& die) {
    const auto attr = die[dwarf::DW_AT::high_pc];
    if (!attr.valid()) {
        throw std::out_of_range{"missing high_pc attribute"};
    }

    using dwarf::value;
    switch (attr.get_type()) {
    case value::type::address:
        return attr.as_address();
    case value::type::constant:
        return die_low_pc(die) + attr.as_uconstant();
    default:
        throw std::runtime_error{"unsupported high_pc encoding"};
    }
}

constexpr std::uint8_t op_fbreg = 0x91;
constexpr std::uint8_t op_breg0 = 0x70;
constexpr std::uint8_t op_bregx = 0x92;
constexpr std::uint8_t op_reg0 = 0x50;
constexpr std::uint8_t op_regx = 0x90;
constexpr std::uint8_t op_addr = 0x03;
constexpr std::uint8_t op_constu = 0x10;
constexpr std::uint8_t op_consts = 0x11;
constexpr std::uint8_t op_stack_value = 0x9f;

struct location_result {
    enum class kind { memory, value };
    kind storage{kind::value};
    uint64_t value{0};
};

struct variable_value {
    std::string name;
    std::vector<std::uint8_t> bytes;
    bool is_parameter{false};
};

uint64_t decode_uleb128(const std::uint8_t* data, std::size_t size, std::size_t& offset) {
    uint64_t result = 0;
    unsigned shift = 0;
    while (offset < size) {
        const auto byte = data[offset++];
        result |= static_cast<uint64_t>(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) {
            break;
        }
        shift += 7;
    }
    return result;
}

int64_t decode_sleb128(const std::uint8_t* data, std::size_t size, std::size_t& offset) {
    int64_t result = 0;
    unsigned shift = 0;
    std::uint8_t byte = 0;
    while (offset < size) {
        byte = data[offset++];
        result |= static_cast<int64_t>(byte & 0x7f) << shift;
        shift += 7;
        if ((byte & 0x80) == 0) {
            break;
        }
    }
    if ((shift < 64) && (byte & 0x40)) {
        result |= -((int64_t)1 << shift);
    }
    return result;
}

std::optional<std::size_t> resolve_type_size(dwarf::die type_die, std::size_t pointer_size) {
    if (!type_die.valid()) {
        return std::nullopt;
    }

    while (type_die.valid()) {
        const auto size_attr = type_die[dwarf::DW_AT::byte_size];
        if (size_attr.valid()) {
            return static_cast<std::size_t>(size_attr.as_uconstant());
        }

        switch (type_die.tag) {
        case dwarf::DW_TAG::pointer_type:
        case dwarf::DW_TAG::reference_type:
        case dwarf::DW_TAG::rvalue_reference_type:
            return pointer_size;
        case dwarf::DW_TAG::const_type:
        case dwarf::DW_TAG::volatile_type:
        case dwarf::DW_TAG::typedef_:
        case dwarf::DW_TAG::restrict_type: {
            const auto base = type_die[dwarf::DW_AT::type];
            if (!base.valid()) {
                return std::nullopt;
            }
            type_die = base.as_reference();
            continue;
        }
        default:
            return std::nullopt;
        }
    }
    return std::nullopt;
}

std::string format_bytes(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream os;
    os << "0x" << std::setfill('0');
    for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
        os << std::hex << std::setw(2) << static_cast<unsigned>(*it);
    }
    return os.str();
}

std::optional<location_result> evaluate_location(debugger& dbg,
                                                 const dwarf::value& loc_attr,
                                                 uint64_t frame_base,
                                                 std::size_t pointer_size) {
    std::size_t size = 0;
    const auto* data = static_cast<const std::uint8_t*>(loc_attr.as_block(&size));
    if (!data || size == 0) {
        return std::nullopt;
    }

    std::size_t offset = 0;
    location_result result{};
    bool have_result = false;

    while (offset < size) {
        const auto op = data[offset++];
        if (op == op_fbreg) {
            const auto rel = decode_sleb128(data, size, offset);
            const auto addr = frame_base + static_cast<int64_t>(rel);
            result.storage = location_result::kind::memory;
            result.value = addr;
            have_result = true;
            continue;
        }

        if (op >= op_breg0 && op <= op_breg0 + 31) {
            const auto regno = static_cast<int>(op - op_breg0);
            const auto rel = decode_sleb128(data, size, offset);
            const auto base = get_register_value_from_dwarf_register(dbg.traced_pid(), regno);
            result.storage = location_result::kind::memory;
            result.value = base + static_cast<int64_t>(rel);
            have_result = true;
            continue;
        }

        if (op == op_bregx) {
            const auto regno = static_cast<int>(decode_uleb128(data, size, offset));
            const auto rel = decode_sleb128(data, size, offset);
            const auto base = get_register_value_from_dwarf_register(dbg.traced_pid(), regno);
            result.storage = location_result::kind::memory;
            result.value = base + static_cast<int64_t>(rel);
            have_result = true;
            continue;
        }

        if (op >= op_reg0 && op <= op_reg0 + 31) {
            const auto regno = static_cast<int>(op - op_reg0);
            result.storage = location_result::kind::value;
            result.value = get_register_value_from_dwarf_register(dbg.traced_pid(), regno);
            have_result = true;
            continue;
        }

        if (op == op_regx) {
            const auto regno = static_cast<int>(decode_uleb128(data, size, offset));
            result.storage = location_result::kind::value;
            result.value = get_register_value_from_dwarf_register(dbg.traced_pid(), regno);
            have_result = true;
            continue;
        }

        if (op == op_addr) {
            if (offset + pointer_size > size) {
                return std::nullopt;
            }
            uint64_t addr = 0;
            for (std::size_t i = 0; i < pointer_size; ++i) {
                addr |= static_cast<uint64_t>(data[offset++]) << (8 * i);
            }
            result.storage = location_result::kind::memory;
            result.value = addr;
            have_result = true;
            continue;
        }

        if (op == op_constu) {
            const auto value = decode_uleb128(data, size, offset);
            result.storage = location_result::kind::value;
            result.value = value;
            have_result = true;
            continue;
        }

        if (op == op_consts) {
            const auto value = decode_sleb128(data, size, offset);
            result.storage = location_result::kind::value;
            result.value = static_cast<uint64_t>(value);
            have_result = true;
            continue;
        }

        if (op == op_stack_value) {
            have_result = true;
            continue;
        }

        return std::nullopt;
    }

    if (!have_result) {
        return std::nullopt;
    }

    return result;
}

uint64_t compute_frame_base(debugger& dbg, const dwarf::die& func_die, std::size_t pointer_size) {
    const auto rbp_value = get_register_value(dbg.traced_pid(), reg::rbp);
    const auto attr = func_die[dwarf::DW_AT::frame_base];
    if (attr.valid()) {
        std::size_t size = 0;
        const auto* data = static_cast<const std::uint8_t*>(attr.as_block(&size));
        if (data && size == 1 && data[0] == 0x9c) { // DW_OP_call_frame_cfa
            return rbp_value + pointer_size * 2;
        }
    }
    return rbp_value;
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
        if (!cmdline.empty()) {
            handle_command(cmdline);
            if (m_should_exit) {
                break;
            }
        }
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

    if (command == "quit" || command == "q") {
        std::cout << "bye\n";
        if (kill(m_pid, SIGKILL) == -1 && errno != ESRCH) {
            perror("kill");
        }
        m_should_exit = true;
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

    if (command == "break" || command == "b") {
        if (args.size() < 2) {
            report_error("Usage: break <address|file:line|function>");
            return;
        }
        const auto& spec = args[1];
        try {
            if (spec.size() > 2 && spec[0] == '0' && (spec[1] == 'x' || spec[1] == 'X')) {
                set_breakpoint_at_address(static_cast<std::intptr_t>(parse_integer(spec)));
            } else if (spec.find(':') != std::string::npos) {
                const auto file_and_line = split(spec, ':');
                if (file_and_line.size() != 2) {
                    throw std::invalid_argument("invalid file:line breakpoint specifier");
                }
                set_breakpoint_at_source_line(file_and_line[0], std::stoi(file_and_line[1]));
            } else {
                set_breakpoint_at_function(spec);
            }
        } catch (const std::exception& ex) {
            report_error(ex);
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

    if (is_prefix(command, "backtrace") || is_prefix(command, "bt")) {
        print_backtrace();
        return;
    }

    if (command == "vars") {
        print_variables();
        return;
    }

    if (command == "p" || command == "print") {
        if (args.size() < 2) {
            report_error("Usage: p <variable-name>");
            return;
        }
        print_variable(args[1]);
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

void debugger::print_variables() {
    try {
        const auto func = get_function_from_pc(get_offset_pc());
        const auto ptr_size = address_size();
        const auto frame_base = compute_frame_base(*this, func, ptr_size);
        std::vector<variable_value> vars;

        for (const auto& child : func) {
            if (child.tag != dwarf::DW_TAG::variable &&
                child.tag != dwarf::DW_TAG::formal_parameter) {
                continue;
            }

            const auto name_attr = child[dwarf::DW_AT::name];
            const auto location_attr = child[dwarf::DW_AT::location];
            if (!name_attr.valid() || !location_attr.valid()) {
                continue;
            }

            dwarf::die type_die;
            if (const auto type_attr = child[dwarf::DW_AT::type]; type_attr.valid()) {
                type_die = type_attr.as_reference();
            }

            const auto size_opt = resolve_type_size(type_die, ptr_size);
            const auto byte_width = size_opt.value_or(ptr_size);
            if (byte_width == 0) {
                continue;
            }

            const auto location = evaluate_location(*this, location_attr, frame_base, ptr_size);
            if (!location) {
                continue;
            }

            variable_value value;
            value.name = name_attr.as_string();
            value.is_parameter = (child.tag == dwarf::DW_TAG::formal_parameter);
            value.bytes.resize(byte_width, 0);

            try {
                if (location->storage == location_result::kind::memory) {
                    read_memory(location->value, value.bytes.data(), value.bytes.size());
                } else {
                    const auto copy = std::min<std::size_t>(value.bytes.size(), sizeof(location->value));
                    std::memcpy(value.bytes.data(), &location->value, copy);
                }
            } catch (const std::exception&) {
                continue;
            }

            vars.push_back(std::move(value));
        }

        if (vars.empty()) {
            std::cout << "(no variables)\n";
            return;
        }
        for (const auto& entry : vars) {
            std::cout << entry.name << " = " << format_bytes(entry.bytes) << '\n';
        }
    } catch (const std::exception& ex) {
        report_error(std::string("vars: ") + ex.what());
    }
}

void debugger::print_variable(const std::string& name) {
    try {
        const auto func = get_function_from_pc(get_offset_pc());
        const auto ptr_size = address_size();
        const auto frame_base = compute_frame_base(*this, func, ptr_size);
        bool found = false;

        for (const auto& child : func) {
            if (child.tag != dwarf::DW_TAG::variable &&
                child.tag != dwarf::DW_TAG::formal_parameter) {
                continue;
            }
            const auto name_attr = child[dwarf::DW_AT::name];
            const auto location_attr = child[dwarf::DW_AT::location];
            if (!name_attr.valid() || name_attr.as_string() != name || !location_attr.valid()) {
                continue;
            }

            dwarf::die type_die;
            if (const auto type_attr = child[dwarf::DW_AT::type]; type_attr.valid()) {
                type_die = type_attr.as_reference();
            }

            const auto size_opt = resolve_type_size(type_die, ptr_size);
            const auto byte_width = size_opt.value_or(ptr_size);
            if (byte_width == 0) {
                break;
            }

            const auto location = evaluate_location(*this, location_attr, frame_base, ptr_size);
            if (!location) {
                break;
            }

            std::vector<std::uint8_t> buffer(byte_width, 0);
            try {
                if (location->storage == location_result::kind::memory) {
                    read_memory(location->value, buffer.data(), buffer.size());
                } else {
                    const auto copy = std::min<std::size_t>(buffer.size(), sizeof(location->value));
                    std::memcpy(buffer.data(), &location->value, copy);
                }
            } catch (const std::exception&) {
                break;
            }

            std::cout << name << " = " << format_bytes(buffer) << '\n';
            found = true;
            break;
        }
        if (!found) {
            report_error("unknown variable: " + name);
        }
    } catch (const std::exception& ex) {
        report_error(std::string("p: ") + ex.what());
    }
}

void debugger::read_memory(uint64_t address, std::uint8_t* buffer, std::size_t length) {
    std::size_t copied = 0;
    while (copied < length) {
        errno = 0;
        const auto data = ptrace(PTRACE_PEEKDATA,
                                 m_pid,
                                 reinterpret_cast<void*>(address + copied),
                                 nullptr);
        if (data == -1 && errno) {
            throw std::runtime_error(std::string("ptrace(PTRACE_PEEKDATA) failed: ") + std::strerror(errno));
        }
        const auto chunk = std::min<std::size_t>(sizeof(long), length - copied);
        std::memcpy(buffer + copied, &data, chunk);
        copied += chunk;
    }
}

std::size_t debugger::address_size() const {
    return sizeof(std::uintptr_t);
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

    const auto func_entry = die_low_pc(func);
    const auto func_end = die_high_pc(func);

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
                auto low_pc = die_low_pc(die);
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

void debugger::print_backtrace() {
    std::ios_base::fmtflags original_flags{std::cout.flags()};
    try {
        constexpr std::size_t max_frames = 64;
        std::size_t frame_index = 0;

        auto current_pc = get_pc();
        auto frame_pointer = get_register_value(m_pid, reg::rbp);

        while (frame_index < max_frames) {
            const auto func = get_function_from_pc(offset_load_address(current_pc));
            const auto link_addr = dwarf::at_low_pc(func);
            const auto runtime_addr = offset_dwarf_address(link_addr);
            std::string func_name;
            try {
                func_name = dwarf::at_name(func);
            } catch (...) {
                func_name.clear();
            }

            std::cout << "frame #" << frame_index++ << ": 0x"
                      << std::hex << runtime_addr << std::dec << ' '
                      << (func_name.empty() ? "<unknown>" : func_name) << '\n';

            if (func_name == "main") {
                break;
            }

            if (frame_pointer == 0) {
                break;
            }

            const auto return_address = read_memory(frame_pointer + sizeof(uint64_t));
            if (return_address == 0) {
                break;
            }

            const auto next_frame = read_memory(frame_pointer);
            if (next_frame == 0 || next_frame <= frame_pointer) {
                break;
            }

            frame_pointer = next_frame;
            current_pc = return_address - 1;
        }
    } catch (const std::out_of_range&) {
        // Unwinding reached code without DWARF coverage (e.g. runtime startup).
    } catch (const std::exception& ex) {
        report_error(std::string("backtrace failed: ") + ex.what());
    }
    std::cout.flags(original_flags);
}
