#!/usr/bin/python3
from bcc import BPF
import time

# eBPF-программа на C
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(start, u32, u64); // Карта для хранения времени начала вызова

// Перехват входа в системный вызов execve
int syscall__execve(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

// Перехват выхода из системного вызова execve
int do_ret_sys_execve(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp, delta;

    // Получаем время начала из карты
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0; // Нет записи о начале вызова
    }

    // Вычисляем разницу времени
    delta = bpf_ktime_get_ns() - *tsp;

    // Получаем имя процесса
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Выводим результат
    bpf_trace_printk("%s %llu\\n", comm, delta);

    // Удаляем запись из карты
    start.delete(&pid);
    return 0;
}
"""

# Загрузка eBPF-программы
b = BPF(text=bpf_program)

# Привязка к системному вызову execve
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

# Заголовок вывода
print("%-16s %-6s" % ("COMM", "TIME_NS"))

# Чтение и вывод данных
try:
    while True:
        time.sleep(1)
        for line in b.trace_fields():
            fields = line[5].decode().split()
            if len(fields) == 2:
                comm, delta = fields
                print("%-16s %-6s" % (comm, delta))
except KeyboardInterrupt:
    print("Завершение трассировки")
