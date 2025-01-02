#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/workqueue.h>

#include "allowlist.h"
#include "arch.h"
#include "core_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "throne_tracker.h"

// 定义一个工作队列结构体指针
static struct workqueue_struct *ksu_workqueue;

// 将工作项添加到工作队列
bool ksu_queue_work(struct work_struct *work)
{
    return queue_work(ksu_workqueue, work);
}

// 声明外部函数，用于处理 execveat 系统调用
extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
                    void *argv, void *envp, int *flags);

extern int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr,
                    void *argv, void *envp, int *flags);

// 处理 execveat 系统调用
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
            void *envp, int *flags)
{
    ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags);
    return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
                        flags);
}

// 声明外部函数，用于初始化和退出 sucompat 和 ksud
extern void ksu_sucompat_init();
extern void ksu_sucompat_exit();
extern void ksu_ksud_init();
extern void ksu_ksud_exit();

// KernelSU 的初始化函数
int __init kernelsu_init(void)
{
#ifdef CONFIG_KSU_DEBUG
    pr_alert("*************************************************************");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("**                                                         **");
    pr_alert("**         You are running KernelSU in DEBUG mode          **");
    pr_alert("**                                                         **");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("*************************************************************");
#endif

    // 初始化核心功能
    ksu_core_init();

    // 分配有序工作队列
    ksu_workqueue = alloc_ordered_workqueue("kernelsu_work_queue", 0);

    // 初始化白名单和 throne tracker
    ksu_allowlist_init();
    ksu_throne_tracker_init();

#ifdef CONFIG_KPROBES
    // 初始化 sucompat 和 ksud
    ksu_sucompat_init();
    ksu_ksud_init();
#else
    pr_alert("KPROBES is disabled, KernelSU may not work, please check https://kernelsu.org/guide/how-to-integrate-for-non-gki.html");
#endif

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
    // 删除模块对象
    kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
    return 0;
}

// KernelSU 的退出函数
void kernelsu_exit(void)
{
    // 退出白名单和 throne tracker
    ksu_allowlist_exit();
    ksu_throne_tracker_exit();

    // 销毁工作队列
    destroy_workqueue(ksu_workqueue);

#ifdef CONFIG_KPROBES
    // 退出 sucompat 和 ksud
    ksu_ksud_exit();
    ksu_sucompat_exit();
#endif

    // 退出核心功能
    ksu_core_exit();
}

// 注册初始化和退出函数
module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
