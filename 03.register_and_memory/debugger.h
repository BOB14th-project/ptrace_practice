#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "breakpoint.h"

class debugger {
public:
    debugger(std::string prog_name, pid_t pid)
        : m_prog_name{std::move(prog_name)}, m_pid{pid} {}

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
    void step_over_breakpoint();
    int wait_for_signal(bool report = true);

    static std::vector<std::string> split(const std::string &s, char delimiter);
    static bool is_prefix(const std::string &s, const std::string &of);

    std::string m_prog_name;
    pid_t m_pid;
    std::unordered_map<std::intptr_t,breakpoint> m_breakpoints;
};
