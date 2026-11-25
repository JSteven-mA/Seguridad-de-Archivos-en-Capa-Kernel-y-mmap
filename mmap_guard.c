/*
 * mmap_guard.c
 * ---------------------------------------------------------------------
 * Parcial SO 2026-2 - Seguridad de Archivos en Capa Kernel y mmap
 *
 * Modulo de kernel (LKM) que instala un kprobe sobre security_mmap_file
 * (el gancho LSM que el kernel invoca justo antes de crear la VMA en
 * do_mmap()). Si el archivo que se intenta mapear coincide con una ruta
 * protegida (parametro de modulo) y se solicita escritura compartida
 * (PROT_WRITE + MAP_SHARED), el acceso se deniega y se audita.
 *
 * Por que un kprobe sobre security_mmap_file y no la syscall table:
 *   - security_mmap_file es el punto estable donde los LSM reales
 *     (SELinux/AppArmor) tambien intervienen: se ejecuta ANTES de que
 *     exista la VMA, con los argumentos (file, prot, flags) ya resueltos.
 *   - No requiere parchear memoria de solo lectura del kernel (no se
 *     toca CR0.WP ni la tabla de syscalls), evitando condiciones de
 *     carrera e inestabilidad tipo rootkit.
 *   - Es compatible con kernels 5.x/6.x sin recompilar el kernel.
 *
 * Auditoria: cada evento (permitido o denegado) se registra en un
 * buffer circular expuesto en /proc/mmap_guard.
 *
 * Compilacion: make  (ver Makefile)
 * Carga:       sudo insmod mmap_guard.ko protected_path="/ruta/secreta.txt"
 * Descarga:    sudo rmmod mmap_guard
 * Auditoria:   cat /proc/mmap_guard
 * Log kernel:  dmesg | tail
 * ---------------------------------------------------------------------
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/mman.h>
#include <linux/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Parcial SO 2026-2");
MODULE_DESCRIPTION("Auditoria/bloqueo de mmap sobre archivos protegidos via kprobe en security_mmap_file");

/* ------------------------------------------------------------------ */
/* Parametros de modulo                                                */
/* ------------------------------------------------------------------ */
static char *protected_path = "/tmp/secreto.txt";
module_param(protected_path, charp, 0444);
MODULE_PARM_DESC(protected_path, "Ruta absoluta del archivo a proteger de mmap de escritura compartida");

static bool block_mode = true;
module_param(block_mode, bool, 0644);
MODULE_PARM_DESC(block_mode, "true = bloquear accesos; false = solo auditar (modo pasivo)");

/* ------------------------------------------------------------------ */
/* Buffer de auditoria circular (muy simplificado, con spinlock)      */
/* ------------------------------------------------------------------ */
#define LOG_ENTRIES 256
#define LOG_LINE_LEN 192

struct audit_entry {
	char line[LOG_LINE_LEN];
};

static struct audit_entry audit_log[LOG_ENTRIES];
static unsigned int log_head;
static unsigned int log_count;
static DEFINE_SPINLOCK(log_lock);

static void audit_add(const char *fmt, ...)
{
	va_list args;
	unsigned long flags;
	struct audit_entry *e;

	spin_lock_irqsave(&log_lock, flags);
	e = &audit_log[log_head];
	va_start(args, fmt);
	vsnprintf(e->line, LOG_LINE_LEN, fmt, args);
	va_end(args);
	log_head = (log_head + 1) % LOG_ENTRIES;
	if (log_count < LOG_ENTRIES)
		log_count++;
	spin_unlock_irqrestore(&log_lock, flags);

	/* tambien al log del kernel, para seguimiento en vivo con dmesg */
	printk(KERN_INFO "mmap_guard: %s\n", e->line);
}

/* ------------------------------------------------------------------ */
/* /proc/mmap_guard : volcado del buffer de auditoria                 */
/* ------------------------------------------------------------------ */
static int proc_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	unsigned int i, idx;

	spin_lock_irqsave(&log_lock, flags);
	for (i = 0; i < log_count; i++) {
		idx = (log_head + LOG_ENTRIES - log_count + i) % LOG_ENTRIES;
		seq_printf(m, "%s\n", audit_log[idx].line);
	}
	spin_unlock_irqrestore(&log_lock, flags);
	return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops proc_fops = {
	.proc_open    = proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};
#else
static const struct file_operations proc_fops = {
	.owner   = THIS_MODULE,
	.open    = proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};
#endif

static struct proc_dir_entry *proc_entry;

/* ------------------------------------------------------------------ */
/* kprobe sobre security_mmap_file(struct file *file, unsigned long   */
/*                                  prot, unsigned long flags)        */
/* ------------------------------------------------------------------ */
static struct kprobe kp = {
	.symbol_name = "security_mmap_file",
};

/*
 * pre_handler: se ejecuta ANTES de security_mmap_file().
 * En x86_64, los 3 primeros argumentos enteros/puntero llegan en
 * regs->di, regs->si, regs->dx (convencion System V AMD64).
 *
 * Para FORZAR la denegacion de forma robusta y portable entre
 * arquitecturas, en vez de reescribir el valor de retorno a mano,
 * usamos el propio argumento 'prot' como vector de decision y
 * devolvemos 1 para que el kprobe module nos permita (si se
 * implementara con jprobe/fexit se podria alterar directamente el
 * valor de retorno; aqui documentamos ambas rutas).
 */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file;
	unsigned long prot, flags;
	char pathbuf[256];
	char *pathname;

#ifdef CONFIG_X86_64
	file  = (struct file *) regs->di;
	prot  = (unsigned long) regs->si;
	flags = (unsigned long) regs->dx;
#else
	/* En otras arquitecturas, resolver segun su ABI de llamadas.
	 * Se deja como punto de extension documentado en el informe. */
	return 0;
#endif

	if (!file || !file->f_path.dentry)
		return 0;

	pathname = d_path(&file->f_path, pathbuf, sizeof(pathbuf));
	if (IS_ERR(pathname))
		return 0;

	if (strcmp(pathname, protected_path) != 0)
		return 0; /* no es el archivo protegido: dejar pasar */

	/* MAP_SHARED = 0x01 ; PROT_WRITE = 0x02 (ver <asm-generic/mman-common.h>) */
	if ((flags & MAP_SHARED) && (prot & PROT_WRITE)) {
		audit_add("%s pid=%d uid=%d file=%s prot=0x%lx flags=0x%lx",
			   block_mode ? "DENY" : "AUDIT",
			   task_pid_nr(current),
			   from_kuid(&init_user_ns, current_uid()),
			   pathname, prot, flags);

		if (block_mode) {
			/*
			 * Tecnica de "retorno forzado" via kprobe: solo
			 * sobreescribir rax no basta, porque la funcion
			 * security_mmap_file() real se ejecuta despues del
			 * pre_handler y pisa ese valor con su propio retorno.
			 * Para bloquear de verdad, se mueve el instruction
			 * pointer directamente a la direccion de retorno
			 * (leida de la pila) y se ajusta el stack pointer,
			 * simulando un "ret" inmediato con -EPERM en rax.
			 * Asi la funcion original nunca llega a ejecutarse.
			 *
			 * Para produccion, lo recomendado es migrar esta
			 * logica a un modulo LSM real (security_add_hooks())
			 * o a BPF_PROG_TYPE_LSM, donde devolver -EPERM es la
			 * via oficial y soportada por el kernel.
			 */
			unsigned long ret_addr = *(unsigned long *)regs->sp;

			regs->ip = ret_addr;
			regs->sp += sizeof(unsigned long);
			regs->ax = -EPERM;

			/*
			 * Devolver 1 le indica al nucleo de kprobes que ya
			 * tomamos el control de la ejecucion (regs->ip ya
			 * apunta al llamador) y que NO debe ejecutar la
			 * instruccion original de security_mmap_file().
			 * Si devolvieramos 0 aqui, el kernel igual ejecutaria
			 * la funcion real y pisaria nuestro -EPERM.
			 */
			return 1;
		}
	} else {
		audit_add("ALLOW pid=%d uid=%d file=%s prot=0x%lx flags=0x%lx",
			   task_pid_nr(current),
			   from_kuid(&init_user_ns, current_uid()),
			   pathname, prot, flags);
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/* Init / Exit                                                         */
/* ------------------------------------------------------------------ */
static int __init mmap_guard_init(void)
{
	int ret;

	kp.pre_handler = handler_pre;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		printk(KERN_ERR "mmap_guard: fallo al registrar kprobe: %d\n", ret);
		return ret;
	}

	proc_entry = proc_create("mmap_guard", 0444, NULL, &proc_fops);
	if (!proc_entry) {
		unregister_kprobe(&kp);
		printk(KERN_ERR "mmap_guard: fallo al crear /proc/mmap_guard\n");
		return -ENOMEM;
	}

	printk(KERN_INFO "mmap_guard: cargado. Protegiendo '%s' (block_mode=%d)\n",
	       protected_path, block_mode);
	return 0;
}

static void __exit mmap_guard_exit(void)
{
	unregister_kprobe(&kp);
	if (proc_entry)
		proc_remove(proc_entry);
	printk(KERN_INFO "mmap_guard: descargado\n");
}

module_init(mmap_guard_init);
module_exit(mmap_guard_exit);
