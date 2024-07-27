#include <stdlib.h>
#include <sys/types.h>
struct Registers;
int inject(pid_t processId, char* shellCode);
int attach_target_process(pid_t processId);
int inject_shellcode(pid_t targetProcess, struct Registers targetProcessRegisters);
int deatch_target_process(pid_t processId);
void log_syscall_failure(int syscallReturnCode, char* error_message);
struct Registers get_target_process_registers(pid_t processId); 

