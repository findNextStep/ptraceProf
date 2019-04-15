#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <stdio.h>
#include <chrono>
#include <thread>

void trace_for(const int pid) {
    int status;
    while(true) {
        wait(&status);
        if(WIFEXITED(status)) { //子进程发送退出信号，退出循环
            break;
        }
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        // int ins = ptrace(PTRACE_PEEKDATA, pid, regs.rip, 0);
        // printf("%12llx\t%16llx\n", regs.rip,ins);
        printf("orig_eax = %ld \n", regs.rip);
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    }
}

void trace_fore(const int pid) {
    long orig_eax;
    int status;
    while(1) {
        //等待子进程信号
        wait(&status);
        if(WIFEXITED(status)) { //子进程发送退出信号，退出循环
            break;
        }
        //调用ptrace从子进程取数据
        orig_eax = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
        printf("orig_eax = %ld \n", orig_eax);
        //让子进程继续执行
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    }
}

void some_time_trace(const int pid) {
    int status;
    long orig_eax;
    while(1) {
        ptrace(PTRACE_ATTACH, pid, 0, 0);
        wait(&status);
        // std::this_thread::sleep_for(std::chrono::nanoseconds(10));
        printf("test\n");
        // wait(&status);
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        fprintf(stdout, "after sigle step\n");
        wait(&status);
        printf("after wait\n");
        if(WIFEXITED(status)) { //子进程发送退出信号，退出循环
            break;
        }
        long orig_eax = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        wait(&status);
        if(WIFEXITED(status)) { //子进程发送退出信号，退出循环
            break;
        }
        long orig_eax2 = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
        ptrace(PTRACE_CONT, pid, 0, 0);
        fprintf(stdout, "orig_eax = %ld \n", orig_eax);
        fprintf(stdout, "orig_eax = %ld \n\n", orig_eax2);
        ptrace(PTRACE_DETACH, pid, 0, 0);
    }
}

int main() {
    int child = fork();
    if(child == 0) {
        ptrace(PT_TRACE_ME, 0, 0, 0);
        // execl("/bin/ls", "ls");
        execl("./a.out", "out");
    } else {
        some_time_trace(child);
    }
}
