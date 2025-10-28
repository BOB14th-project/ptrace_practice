#pragma once

#include <csignal>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <unordered_map>
#include <vector>

#include <dwarf++.hh>
#include <elf++.hh>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "breakpoint.h"

class debugger {
public:
    debugger(std::string prog_name, pid_t pid)
        : m_prog_name{std::move(prog_name)}
        , m_pid{pid} {
        const auto fd = open(m_prog_name.c_str(), O_RDONLY);
        if (fd == -1) {
            throw std::runtime_error("failed to open " + m_prog_name);
        }

        m_elf = elf::elf{elf::create_mmap_loader(fd)};
        m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
        close(fd);
    }

    void run();
    void set_breakpoint_at_address(std::intptr_t addr);

private:
    void handle_command(const std::string &line);
    void continue_execution();
    void dump_registers();
    uint64_t read_memory(uint64_t address);
    void write_memory(uint64_t address, uint64_t value);
    uint64_t get_pc() const;
    void set_pc(uint64_t pc);
    uint64_t get_offset_pc() const;
    void step_over_breakpoint();
    void single_step_instruction();
    void single_step_instruction_with_breakpoint_check();
    void step_out();
    void remove_breakpoint(std::intptr_t addr);
    void step_in();
    uint64_t offset_dwarf_address(uint64_t addr) const;
    void step_over();
    int wait_for_signal(bool report = true);
    dwarf::die get_function_from_pc(uint64_t pc);
    dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);
    void initialize_load_address();
    uint64_t offset_load_address(uint64_t addr) const;
    void print_source(const std::string& file_name, unsigned line, unsigned n_lines_context = 2);
    siginfo_t get_signal_info();
    void handle_sigtrap(siginfo_t info);

    static std::vector<std::string> split(const std::string &s, char delimiter);
    static bool is_prefix(const std::string &s, const std::string &of);

    std::string m_prog_name;
    pid_t m_pid;
    std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;

    elf::elf m_elf;
    dwarf::dwarf m_dwarf;
    uint64_t m_load_address{0};
};
