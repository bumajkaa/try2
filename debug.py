#!/usr/bin/python3
from bcc import BPF
import time

# eBPF-программа на C
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    char comm[TASK_COMM_LEN];
    u64 delta;
};

BPF_HASH(start, u32, u64); // Карта для хранения времени начала вызова
BPF_PERF_OUTPUT(events);   // Вывод событий в пользовательское пространство

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
    struct data_t data = {};

    // Получаем время начала из карты
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0; // Нет записи о начале вызова
    }

    // Вычисляем разницу времени
    delta = bpf_ktime_get_ns() - *tsp;
    data.delta = delta;

    // Получаем имя процесса
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Отправляем данные в пользовательское пространство
    events.perf_submit(ctx, &data, sizeof(data));

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

# Обработка событий
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-16s %-6s" % (event.comm.decode('utf-8'), event.delta))

b["events"].open_perf_buffer\\[0]open_perf_buffer()

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Завершение трассировки")
