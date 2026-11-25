# mmap_guard

Módulo de kernel (LKM) de demostración para el Parcial 2 de Sistemas Operativos:
audita y opcionalmente bloquea `mmap(MAP_SHARED | PROT_WRITE)` sobre un archivo
protegido, mediante un **kprobe** instalado sobre el gancho LSM
`security_mmap_file`.

## Requisitos

```bash
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r) gcc make
```

Ejecutar en una **VM de laboratorio** (VirtualBox/QEMU/UTM). Un módulo de
kernel con errores puede causar un *kernel panic*; toma un snapshot antes
de cargarlo por primera vez.

## Compilar

```bash
make
```

Esto genera `mmap_guard.ko`.

## Preparar el archivo protegido

```bash
echo "contenido confidencial" > /tmp/secreto.txt
```

## Cargar el módulo

```bash
sudo insmod mmap_guard.ko protected_path="/tmp/secreto.txt" block_mode=1
dmesg | tail
```

- `protected_path`: ruta absoluta del archivo a vigilar.
- `block_mode=1`: deniega (`-EPERM`) los `mmap` de escritura compartida sobre
  ese archivo. `block_mode=0`: solo audita, no bloquea.

## Probar

```bash
cd /tmp && python3 /ruta/a/test_mmap_access.py
cat /proc/mmap_guard
```

Deberías ver en `/proc/mmap_guard` (y en `dmesg`) líneas como:

```
DENY pid=1234 uid=1000 file=/tmp/secreto.txt prot=0x3 flags=0x1
ALLOW pid=1235 uid=1000 file=/tmp/secreto.txt prot=0x3 flags=0x2
ALLOW pid=1236 uid=1000 file=/tmp/secreto.txt prot=0x1 flags=0x1
```

## Prueba de condición de carrera (Dirty COW, pedagógica)

```bash
chmod +x test_race_dirtycow.sh
./test_race_dirtycow.sh
```

Verifica que, en el kernel actual (ya parchado), el archivo de solo lectura
nunca cambia pese a la carrera `madvise(MADV_DONTNEED)` / escritura.

## Descargar el módulo

```bash
sudo rmmod mmap_guard
dmesg | tail
```

## Medición de overhead (para la Parte IV del informe)

```bash
# Latencia de mmap() con/sin el módulo cargado
strace -T -e trace=mmap python3 test_mmap_access.py

# Page faults y estadísticas generales
perf stat -e page-faults,minor-faults,major-faults python3 test_mmap_access.py

# Tiempo específico dentro del kprobe
sudo trace-cmd record -e kprobes
sudo trace-cmd report
```

## Nota sobre una corrección aplicada durante las pruebas

La primera versión solo sobreescribía `regs->ax` en el `pre_handler` del kprobe,
pero la función real `security_mmap_file()` se ejecutaba igual después y pisaba
ese valor, dejando pasar el acceso aunque la auditoría ya marcara `DENY`. La
versión final de este repo ya incluye la corrección: lee la dirección de
retorno desde la pila, mueve `regs->ip` hacia ella, ajusta `regs->sp`, fija
`regs->ax = -EPERM`, y devuelve `1` desde el `pre_handler` (en vez de `0`) para
indicarle al núcleo de kprobes que no ejecute la instrucción original. Esto fue
confirmado con pruebas reales: ver la sección de resultados en el informe.

## Notas de diseño (ver informe completo para la justificación)

- Se usa un **kprobe** sobre `security_mmap_file` en vez de parchar la
  *syscall table*: no requiere deshabilitar `CR0.WP`, es compatible con
  kernels 5.x/6.x y se ejecuta en el mismo punto donde intervienen los LSM
  reales (SELinux/AppArmor).
- Para producción se recomienda migrar esta lógica a un **LSM real**
  (`security_add_hooks()`) o a **eBPF LSM** (`BPF_PROG_TYPE_LSM`), ya que
  kprobes crudos no tienen las garantías de seguridad que da el verifier
  de eBPF ni el framework oficial de LSM.
- El límite de esta solución: solo cubre el **alta del VMA** (la llamada a
  `mmap()`), no los accesos de memoria posteriores a través del puntero
  (que van directo a hardware tras el primer *page fault*).
