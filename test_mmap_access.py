#!/usr/bin/env python3
"""
test_mmap_access.py
--------------------------------------------------------------------
Script de prueba para el modulo mmap_guard.

Simula:
  1. Un mmap() MAP_SHARED + PROT_WRITE sobre el archivo protegido
     (debe ser denegado si block_mode=1).
  2. Un mmap() MAP_PRIVATE + PROT_WRITE sobre el mismo archivo
     (debe permitirse: es copy-on-write, no afecta el archivo real).
  3. Un mmap() de solo lectura (debe permitirse siempre).

Uso:
  sudo insmod mmap_guard.ko protected_path="$(pwd)/secreto.txt" block_mode=1
  python3 test_mmap_access.py
  cat /proc/mmap_guard
--------------------------------------------------------------------
"""

import mmap
import os
import sys

TARGET = os.path.join(os.getcwd(), "secreto.txt")


def ensure_target():
    if not os.path.exists(TARGET):
        with open(TARGET, "wb") as f:
            f.write(b"contenido confidencial\n" + b"0" * 4096)
    print(f"[+] Archivo objetivo: {TARGET}")


def try_mmap(mode_desc, open_mode, mmap_prot, mmap_flags):
    print(f"\n--- Caso: {mode_desc} ---")
    try:
        fd = os.open(TARGET, open_mode)
        size = os.fstat(fd).st_size
        m = mmap.mmap(fd, size, flags=mmap_flags, prot=mmap_prot)
        print("    Resultado: mmap() permitido por el kernel.")
        try:
            if mmap_prot & mmap.PROT_WRITE:
                m[0:1] = b"X"
                print("    Escritura en memoria realizada.")
        except Exception as e:
            print(f"    Escritura fallo dentro del mapeo: {e}")
        m.close()
        os.close(fd)
    except PermissionError as e:
        print(f"    Resultado: DENEGADO por el kernel (-EPERM): {e}")
    except OSError as e:
        print(f"    Resultado: Error de SO: {e}")


def main():
    ensure_target()

    # Caso 1: MAP_SHARED + PROT_WRITE -> debe ser bloqueado por mmap_guard
    try_mmap(
        "MAP_SHARED + PROT_WRITE (debe bloquearse)",
        os.O_RDWR,
        mmap.PROT_READ | mmap.PROT_WRITE,
        mmap.MAP_SHARED,
    )

    # Caso 2: MAP_PRIVATE + PROT_WRITE -> COW, debe permitirse
    try_mmap(
        "MAP_PRIVATE + PROT_WRITE (COW, debe permitirse)",
        os.O_RDONLY,
        mmap.PROT_READ | mmap.PROT_WRITE,
        mmap.MAP_PRIVATE,
    )

    # Caso 3: solo lectura -> siempre permitido
    try_mmap(
        "MAP_SHARED + PROT_READ (solo lectura, debe permitirse)",
        os.O_RDONLY,
        mmap.PROT_READ,
        mmap.MAP_SHARED,
    )

    print("\n[+] Revisa 'cat /proc/mmap_guard' y 'dmesg | tail' para ver la auditoria.")


if __name__ == "__main__":
    main()
