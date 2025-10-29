#include "pch.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>

#include <sys/user.h>

#include "register.h"

const std::array<reg_descriptor, n_registers> g_register_descriptors{{
    { reg::r15, 15, "r15" },
    { reg::r14, 14, "r14" },
    { reg::r13, 13, "r13" },
    { reg::r12, 12, "r12" },
    { reg::rbp, 6, "rbp" },
    { reg::rbx, 3, "rbx" },
    { reg::r11, 11, "r11" },
    { reg::r10, 10, "r10" },
    { reg::r9, 9, "r9" },
    { reg::r8, 8, "r8" },
    { reg::rax, 0, "rax" },
    { reg::rcx, 2, "rcx" },
    { reg::rdx, 1, "rdx" },
    { reg::rsi, 4, "rsi" },
    { reg::rdi, 5, "rdi" },
    { reg::orig_rax, -1, "orig_rax" },
    { reg::rip, -1, "rip" },
    { reg::cs, 51, "cs" },
    { reg::rflags, 49, "eflags" },
    { reg::rsp, 7, "rsp" },
    { reg::ss, 52, "ss" },
    { reg::fs_base, 58, "fs_base" },
    { reg::gs_base, 59, "gs_base" },
    { reg::ds, 53, "ds" },
    { reg::es, 50, "es" },
    { reg::fs, 54, "fs" },
    { reg::gs, 55, "gs" },
}};

namespace {

template <typename Predicate>
auto find_descriptor(Predicate&& predicate, const char* error_message)
    -> std::array<reg_descriptor, n_registers>::const_iterator {
    const auto it = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(),
        std::forward<Predicate>(predicate));
    if (it == g_register_descriptors.end()) {
        throw std::out_of_range(error_message);
    }
    return it;
}

std::size_t register_index(reg r) {
    const auto it = find_descriptor(
        [r](const auto& rd) { return rd.r == r; },
        "unknown register");
    return static_cast<std::size_t>(std::distance(g_register_descriptors.begin(), it));
}

std::string to_lower_copy(const std::string& input) {
    std::string copy = input;
    std::transform(copy.begin(), copy.end(), copy.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return copy;
}

} // namespace

uint64_t get_register_value(pid_t pid, reg r) {
    user_regs_struct regs{};
    errno = 0;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        throw std::runtime_error(std::string("ptrace(PTRACE_GETREGS) failed: ") + std::strerror(errno));
    }

    const auto index = register_index(r);
    const auto* data = reinterpret_cast<const uint64_t*>(&regs);
    return *(data + index);
}

void set_register_value(pid_t pid, reg r, uint64_t value) {
    user_regs_struct regs{};
    errno = 0;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        throw std::runtime_error(std::string("ptrace(PTRACE_GETREGS) failed: ") + std::strerror(errno));
    }

    const auto index = register_index(r);
    auto* data = reinterpret_cast<uint64_t*>(&regs);
    *(data + index) = value;

    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == -1) {
        throw std::runtime_error(std::string("ptrace(PTRACE_SETREGS) failed: ") + std::strerror(errno));
    }
}

uint64_t get_register_value_from_dwarf_register(pid_t pid, int dwarf_r) {
    const auto descriptor = find_descriptor(
        [dwarf_r](const auto& rd) { return rd.dwarf_r == dwarf_r; },
        "unknown DWARF register");
    return get_register_value(pid, descriptor->r);
}

reg get_register_from_name(const std::string& name) {
    const auto needle = to_lower_copy(name);
    const auto descriptor = find_descriptor(
        [&needle](const auto& rd) { return rd.name == needle; },
        "unknown register name");
    return descriptor->r;
}

std::string get_register_name(reg r) {
    const auto descriptor = find_descriptor(
        [r](const auto& rd) { return rd.r == r; },
        "unknown register");
    return descriptor->name;
}
