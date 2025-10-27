#include "pch.h"

uint64_t get_register_value(pid_t pid, reg r){
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    //... switch to get the correct register
}

void set_register_value(pid_t pid, reg r, uint64_t value){
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    
    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
        [r](auto&& rd) { return rd.r == r; });
    
        *(reinterpret_cast<uint64_t*>(&regs) + std::distance(begin(g_register_descriptors), it)) = value;
    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

uint64_t get_register_value_from_dwarf_register (pid_t pid, int dwarf_r){
    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
        [dwarf_r](auto&& rd) { return rd.dwarf_r == dwarf_r; });
    if(it == end(g_register_descriptors)){
        throw std::runtime_error("Unknown dwarf register");
    }
    return get_register_value(pid, it->r);
}

