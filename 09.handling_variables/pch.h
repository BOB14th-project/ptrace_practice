#pragma once
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <utility>
#include <cstdint>
#include <optional>

#include <sys/ptrace.h>
#include <sys/personality.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debugger.h"
#include "breakpoint.h"
