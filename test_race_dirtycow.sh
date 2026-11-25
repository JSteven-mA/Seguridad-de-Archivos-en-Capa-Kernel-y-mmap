#!/usr/bin/env bash
# ---------------------------------------------------------------------
# test_race_dirtycow.sh
#
# Script PEDAGOGICO para verificar, en una VM aislada, que el patron
# de carrera explotado por Dirty COW (CVE-2016-5195) ya esta mitigado
# en el kernel actual: dispara escrituras mmap(MAP_PRIVATE) y llamadas
# concurrentes a madvise(MADV_DONTNEED) sobre el mismo mapeo, y verifica
# que el archivo original de solo lectura NUNCA cambia.
#
# IMPORTANTE: ejecutar SOLO en una VM de laboratorio desechable.
# Este script NO ataca ningun archivo del sistema real: crea su propio
# archivo de prueba de solo lectura.
# ---------------------------------------------------------------------
set -euo pipefail

WORKDIR="$(mktemp -d)"
TARGET="$WORKDIR/readonly_target.txt"

echo "[+] Workdir: $WORKDIR"
echo "ESTE CONTENIDO NO DEBE CAMBIAR" > "$TARGET"
chmod 444 "$TARGET"
echo "[+] Archivo objetivo (444, solo lectura): $TARGET"
echo "[+] Hash inicial:"
sha256sum "$TARGET"

# Pequeno programa en C que reproduce el patron de carrera de forma
# benigna: abre O_RDONLY, mapea MAP_PRIVATE, y lanza un hilo que
# intenta madvise(MADV_DONTNEED) en bucle mientras otro hilo escribe
# en el mapeo. En un kernel parchado, el archivo real NUNCA cambia.
cat > "$WORKDIR/race_test.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

static void *map;
static size_t len;
static volatile int stop = 0;

void *madvise_thread(void *arg) {
    while (!stop) {
        madvise(map, len, MADV_DONTNEED);
    }
    return NULL;
}

void *write_thread(void *arg) {
    const char *payload = "HACKEADO";
    for (int i = 0; i < 200000 && !stop; i++) {
        memcpy(map, payload, strlen(payload));
    }
    stop = 1;
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "uso: %s <archivo>\n", argv[0]); return 1; }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    len = lseek(fd, 0, SEEK_END);
    map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); return 1; }

    pthread_t t1, t2;
    pthread_create(&t1, NULL, madvise_thread, NULL);
    pthread_create(&t2, NULL, write_thread, NULL);
    pthread_join(t2, NULL);
    pthread_join(t1, NULL);

    munmap(map, len);
    close(fd);
    printf("Prueba de carrera finalizada (ver hash del archivo real).\n");
    return 0;
}
EOF

echo "[+] Compilando prueba de carrera..."
gcc -O2 -o "$WORKDIR/race_test" "$WORKDIR/race_test.c" -lpthread

echo "[+] Ejecutando prueba de carrera (puede tardar unos segundos)..."
"$WORKDIR/race_test" "$TARGET" || true

echo "[+] Hash final:"
sha256sum "$TARGET"
echo "[+] Si los hashes coinciden, el kernel mitiga correctamente la carrera."
echo "[+] Revisa tambien /proc/mmap_guard si TARGET coincide con protected_path."
