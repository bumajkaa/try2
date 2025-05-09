#!/usr/bin/python3
from bcc import BPF

bpf_program = """
#include <uapi/linux/ptrace.h>

int syscall__execve(struct pt_regs *ctx) {
    bpf_trace_printk("execve called\\n");
    return 0;
}
"""

b = BPF(text=bpf_program)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")

print("Трассировка запущена. Запустите команды в другом терминале...")
b.trace_print()
