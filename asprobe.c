
#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/sched.h>
#include<linux/kprobes.h>
#include<linux/kallsyms.h>

#include <linux/hardirq.h>
#include <linux/debugfs.h>

static struct jprobe debugfs_create_file_probe;
static struct jprobe device_create_probe;
static struct jprobe create_proc_entry_probe;

static asmlinkage int hijack_debugfs_create_file(char* filename, int x, struct dentry d, ...)
{
  printk("ASPROBE :: file '%s' created in debugfs\n", filename);
  jprobe_return();
  return 0;
}

static asmlinkage int hijack_device_create(int w, int x, int y, int z, char* filename,char** args)
{
  char devname[64];
  snprintf(devname,63,filename,args);

  printk("ASPROBE :: file '%s' created in devfs\n", devname);
  jprobe_return();
  return 0;
}

static asmlinkage int hijack_create_proc_entry(char* filename, ...)
{
  printk("ASPROBE :: file '%s' created in procfs\n", filename);
  jprobe_return();
  return 0;
}

int init_module(void)
{
  // hook debugfs
  debugfs_create_file_probe.entry=(kprobe_opcode_t*)hijack_debugfs_create_file;
  debugfs_create_file_probe.kp.addr=(kprobe_opcode_t*)kallsyms_lookup_name("debugfs_create_file");
  register_jprobe(&debugfs_create_file_probe);
  printk("ASPROBE :: debugfs_create_file (debugfs) hooked\n");

  // hook devfs
  device_create_probe.entry=(kprobe_opcode_t*)hijack_device_create;
  device_create_probe.kp.addr=(kprobe_opcode_t*)kallsyms_lookup_name("device_create");
  register_jprobe(&device_create_probe);
  printk("ASPROBE :: device_create (devfs) hooked\n");

  // hook procfs
  create_proc_entry_probe.entry=(kprobe_opcode_t*)hijack_create_proc_entry;
  create_proc_entry_probe.kp.addr=(kprobe_opcode_t*)kallsyms_lookup_name("create_proc_entry");
  register_jprobe(&create_proc_entry_probe);
  printk("ASPROBE :: device_create (procfs) hooked\n");

  return 0;
}

void cleanup_module(void)
{
  unregister_jprobe(&debugfs_create_file_probe);
  unregister_jprobe(&device_create_probe);
  unregister_jprobe(&create_proc_entry_probe);
  printk("ASPROBE :: jprobes unregistered\n");
}

MODULE_LICENSE("GPL");

