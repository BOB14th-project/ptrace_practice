#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Using std::getline for a simple REPL; no external linenoise dependency.

/*
 * minidbg: 작은 ptrace 기반 디버거 예제
 *
 * 전체 흐름(요약):
 *  - 부모 프로세스는 디버거 역할을 합니다.
 *  - 자식 프로세스는 PTRACE_TRACEME를 호출하여 트레이스 대상(tracee)이
 *    되고, 이어서 execvp()로 실제 디버깅 대상 바이너리로 교체됩니다.
 *    exec 후에 발생하는 post-exec SIGTRAP는 부모가 waitpid()로 관찰합니다.
 *  - 부모는 자식의 초기 SIGTRAP을 기다린 뒤 ptrace 옵션을 설정
 *    (예: PTRACE_O_EXITKILL)하고 간단한 REPL을 통해 명령을 받습니다.
 *
 * 파일 내 주요 지점에는 다음과 같은 설명 주석을 추가하여 코드의 흐름을
 * 이해하기 쉽게 했습니다: 프로세스 분기, 초기 정지(post-exec SIGTRAP),
 * PTRACE 옵션 설정, REPL/명령 처리, continue 후 상태 확인 등.
 */

class debugger {
public:
    debugger(std::string prog_name, pid_t pid)
        : m_prog_name{std::move(prog_name)}, m_pid{pid} {}

    void run();

private:
    void handle_command(const std::string &line);
    void continue_execution();

    static std::vector<std::string> split(const std::string &s, char delimiter);
    static bool is_prefix(const std::string &s, const std::string &of);

private:
    std::string m_prog_name;
    pid_t m_pid;
};

void debugger::run() {
    // Wait for the child to stop on its initial SIGTRAP after execve
    int wait_status = 0;
    if (waitpid(m_pid, &wait_status, 0) < 0) {
        perror("waitpid (initial)");
        return;
    }
    // 자식이 즉시 종료한 경우(예: execvp 실패)에는 에러를 출력하고 종료합니다.
    if (WIFEXITED(wait_status)) {
        std::cerr << "[!] Process exited before we could attach (status=" << WEXITSTATUS(wait_status) << ")\n";
        return;
    }

    // 부모는 이제 자식의 post-exec 정지(보통 SIGTRAP)를 관찰한 상태입니다.
    // 아래 ptrace 옵션들을 설정하면 디버깅 동작을 더 깔끔하게 받을 수 있습니다:
    //  - PTRACE_O_EXITKILL: 디버거가 죽으면 tracee도 함께 종료되도록 보장
    //  - PTRACE_O_TRACESYSGOOD: 시스템콜 정지를 다른 정지와 구분하기 쉽게 함
    long r = ptrace(PTRACE_SETOPTIONS, m_pid, 0,
                    PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
    if (r == -1) {
        perror("ptrace(PTRACE_SETOPTIONS)");
    }

    // 간단한 REPL을 실행하여 사용자의 디버거 명령을 입력받습니다.
    // 여기서는 외부 readline 라이브러리 대신 표준 입력의 std::getline을
    // 사용합니다. 입력은 split()으로 파싱되어 handle_command()로 전달됩니다.
    // 현재는 `continue`와 `quit` 정도만 구현되어 있습니다.
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
    } else if (command == "quit" || command == "q") {
    // quit: 디버깅 대상 프로세스를 종료하고 REPL을 빠져나옵니다.
    // 실제 디버거라면 여기서 detach할 수 있지만, 이 예제는 단순히
    // 자식을 kill하여 백그라운드에 남지 않도록 합니다.
    std::cout << "bye\n";
    kill(m_pid, SIGKILL);
    // 추가 작업은 없고, 사용자는 Ctrl+D로 REPL을 종료할 수 있습니다.
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
    // continue로 실행을 재개한 뒤 다시 자식이 멈추거나 종료될 때까지
    // 대기하고 간단한 상태 메시지를 출력합니다. 실제 디버거라면 이
    // 시점에 레지스터나 메모리 검사, 브레이크포인트 처리 등을 하게 됩니다.
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

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <program-to-debug> [args...]\n";
        return 1;
    }

    const char *prog = argv[1];

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // Child: become tracee and exec the target
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            perror("ptrace(PTRACE_TRACEME)");
            _exit(1);
        }
        // Ensure the child stops so the parent can set options after exec
        // The exec* below will deliver SIGTRAP to the parent (post-exec-stop)

        // Build argv for execvp: reuse current argv from argv[1] onward
        std::vector<char *> child_argv;
        child_argv.reserve(argc); // rough
        for (int i = 1; i < argc; ++i) child_argv.push_back(argv[i]);
        child_argv.push_back(nullptr);

        execvp(prog, child_argv.data());
        perror("execvp");
        _exit(1);
    }

    // Parent: run the debugger loop
    debugger dbg{prog, pid};
    dbg.run();

    return 0;
}
