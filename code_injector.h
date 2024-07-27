#include <stdlib.h>
#include <sys/types.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>


int inject(pid_t processId, char* shellCode);
int attach_target_process(pid_t processId);
int inject_shellcode(pid_t targetProcess, struct Registers targetProcessRegisters);
int deatch_target_process(pid_t processId);
void log_syscall_failure(int syscallReturnCode, char* error_message);
struct user_regs_struct get_target_process_registers(pid_t processId); 

