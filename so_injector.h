#include <stdlib.h>
#include <sys/types.h>
int inject_code(pid_t processId);
int attach_target_process(pid_t processId);
int inject_shellcode(pid_t targetProcess, struct targetProcessRegisters);
int deatch_target_process(pid_t processId);
void log_syscall_failure(int syscallReturnCode, char* error_message);
struct get_target_process_registers(pid_t processId); 

