/*
 * Exynos CPU Performance Profiling
 * Author: Jungwook Kim, jwook1.kim@samsung.com
 * Created: 2014
 * Updated: 2016-2020
 */

#include <linux/of.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/uaccess.h>

#include <soc/samsung/dsu_theodul_errata.h>

#include "core.h"

#define DEF_REG_STRUCT(n) \
	struct register_type reg_##n = {	\
	.name = ""#n,	\
	.read_reg = mrs_##n##_read	\
};

static const char *prefix = "xperf";

/* armv8 */
DEF_REG_STRUCT(SCTLR)
DEF_REG_STRUCT(MAIR)
DEF_REG_STRUCT(CPUACTLR)
DEF_REG_STRUCT(CPUECTLR)
DEF_REG_STRUCT(L2CTLR)
DEF_REG_STRUCT(L2ACTLR)
DEF_REG_STRUCT(L2ECTLR)
DEF_REG_STRUCT(MPIDR)
DEF_REG_STRUCT(MIDR)
DEF_REG_STRUCT(REVIDR)

#define SET_CORE_REG(r, v) { .reg = &reg_##r, .val = v }

static struct core_register arm_v8_regs[] = {
	SET_CORE_REG(SCTLR, 0),
	SET_CORE_REG(MAIR, 0),
	SET_CORE_REG(MPIDR, 0),
	SET_CORE_REG(MIDR, 0),
	SET_CORE_REG(REVIDR, 0),
	SET_CORE_REG(CPUACTLR, 1),
	SET_CORE_REG(CPUECTLR, 1),
	SET_CORE_REG(L2CTLR, 1),
	SET_CORE_REG(L2ACTLR, 1),
	SET_CORE_REG(L2ECTLR, 1),
};

static struct core_register arm_a73_regs[] = {
	SET_CORE_REG(SCTLR, 0),
	SET_CORE_REG(MAIR, 0),
	SET_CORE_REG(MPIDR, 0),
	SET_CORE_REG(MIDR, 0),
	SET_CORE_REG(REVIDR, 0),
	SET_CORE_REG(CPUECTLR, 1),
	SET_CORE_REG(L2CTLR, 1),
	SET_CORE_REG(L2ECTLR, 1),
};

enum company_type {
	ARM = 0x41,
	SAMSUNG = 0x53,
};
enum arm_core {
	CORTEX_A53 = 0xD03,
	CORTEX_A73 = 0xD09,
};
static char *arm_core_names[] = {"", "", "", "A53", "", "", "", "", "", "A73", "", "", ""};

static int core = 0;

static enum company_type get_core_company(void)
{
	u32 midr = (u32)mrs_MIDR_read();
	/*
	 *	31:24	- implementer
	 *	23:20	- variant
	 *	19:16	- architecture
	 *	11:4	- part number
	 *	3:0	- revision
	 */
	return (midr >> 24);
}

static int get_core_type(void)
{
	u32 midr = (u32)mrs_MIDR_read();
	/*
	 *	31:24	- implementer
	 *	23:20	- variant
	 *	19:16	- architecture
	 *	11:4	- part number
	 *	3:0	- revision
	 */
	return ((midr & 0xfff0) >> 4);
}

static char buf[PAGE_SIZE];
static int creg_thread_func(void *data)
{
	u64 val;
	enum company_type company = get_core_company();
	int core_type = get_core_type();
	struct core_register *regs = NULL;
	u32 midr = (u32)mrs_MIDR_read();
	u32 revidr = (u32)mrs_REVIDR_read();
	char *core_name;
	int core_reg_count = 0, i;
	int idx = 0;
	int ret = 0;

	memset(buf, 0, PAGE_SIZE);

	switch (company) {
	case ARM:
		idx = core_type - 0xD00;
		if (idx > 0x40) {
			idx -= 0x40;
			core_name = arm_core_names[idx];
		} else {
			if (idx < (sizeof(arm_core_names)/sizeof(char *)))
				core_name = arm_core_names[idx];
			else
				return -EINVAL;
		}
		switch (core_type) {
		case CORTEX_A73:
			regs = arm_a73_regs;
			core_reg_count = ARRAY_SIZE(arm_a73_regs);
			break;
		case CORTEX_A53:
			regs = arm_v8_regs;
			core_reg_count = ARRAY_SIZE(arm_v8_regs);
			break;
		}
		break;
	default:
		core_name = "unknown";
		regs = arm_v8_regs;
		core_reg_count = ARRAY_SIZE(arm_v8_regs);
		break;
	}

	ret += snprintf(buf + ret, PAGE_SIZE - ret, "[%s] r%xp%x revidr=0x%08x\n",
			core_name,
			(midr & 0xf00000) >> 20,
			midr & 0xf,
			revidr);

	if (regs == NULL || !core_reg_count)
		return -EINVAL;

	arm_smcc_disable_clock_gating();
	for (i = 0; i < core_reg_count; ++i) {
		val = regs[i].reg->read_reg();
		ret += snprintf(buf + ret, PAGE_SIZE - ret, "%10s: 0x%016llX\n", regs[i].reg->name, val);
	}
	arm_smcc_enable_clock_gating();

	return 0;
}
//-----------------------------------
static ssize_t show_creg(struct kobject *k, struct kobj_attribute *attr, char *b)
{
	int ret = 0;
	ret += sprintf(b + ret, "%s", buf);
	return ret;
}

static struct task_struct *task;

static ssize_t store_creg(struct kobject *k, struct kobj_attribute *attr, const char *b, size_t count) {
	if (sscanf(b, "%d", &core) != 1)
		return -EINVAL;
	task = kthread_create_on_node(creg_thread_func, NULL, NUMA_NO_NODE, "xperf_core");
	kthread_bind(task, core);
	wake_up_process(task);
	msleep(1000);

	return count;
}
static struct kobj_attribute creg_attr = __ATTR(creg, 0644, show_creg, store_creg);

static struct attribute *core_attrs[] = {
	&creg_attr.attr,
	NULL
};
static struct attribute_group core_group = {
	.attrs = core_attrs,
};


// main
static struct kobject *core_kobj;

int xperf_core_init(struct kobject *kobj)
{
	int ret;

	core_kobj = kobject_create_and_add("core", kobj);
	if (!core_kobj) {
		pr_info("[%s] create node failed: %s\n", prefix, __FILE__);
		return -EINVAL;
	}
	ret = sysfs_create_group(core_kobj, &core_group);
	if (ret) {
		pr_info("[%s] create group failed: %s\n", prefix, __FILE__);
		return -EINVAL;
	}

	return 0;
}
