/* SPDX-License-Identifier: MIT
 * Bounded existing-TID capture: mmap before enable, no periodic disable/re-enable.
 * Build on Linux: aarch64-linux-gnu-gcc -static -O2 -Wall -Wextra -Werror
 *                ete_direct_record.c -o ete-direct-record
 */
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <fcntl.h>

static int event_fd = -1;

static void fail(const char *message)
{
    perror(message);
    if (event_fd >= 0) {
        ioctl(event_fd, PERF_EVENT_IOC_DISABLE, 0);
        close(event_fd);
    }
    exit(2);
}

static unsigned read_uint(const char *path, const char *format)
{
    unsigned value;
    FILE *file = fopen(path, "r");
    if (!file || fscanf(file, format, &value) != 1)
        fail(path);
    fclose(file);
    return value;
}

static void save(const char *directory, const char *name, const void *data, size_t size)
{
    char path[512];
    if (snprintf(path, sizeof(path), "%s/%s", directory, name) >= (int)sizeof(path))
        fail("output path too long");
    FILE *file = fopen(path, "wbx");
    if (!file || fwrite(data, 1, size, file) != size || fclose(file))
        fail("save output");
}

static double monotonic_seconds(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time))
        fail("clock_gettime");
    return time.tv_sec + time.tv_nsec / 1e9;
}

static unsigned long long number(const char *text)
{
    char *end;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 0);
    if (errno || !*text || *end || *text == '-')
        fail("invalid integer");
    return value;
}

static void save_vdso(unsigned long long tid, const char *directory, const char *name)
{
    char path[128], line[512], mapped[256];
    snprintf(path, sizeof(path), "/proc/%llu/maps", tid);
    FILE *maps = fopen(path, "r");
    if (!maps)
        fail("vDSO maps");
    unsigned long low = 0, high = 0, offset = 0;
    int found = 0;
    while (fgets(line, sizeof(line), maps)) {
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s %lx %*s %*s %255s", &low, &high,
                   perms, &offset, mapped) == 5 && !strcmp(mapped, "[vdso]")) {
            found = 1;
            break;
        }
    }
    fclose(maps);
    if (!found || offset || high <= low || high - low > 65536)
        fail("invalid vDSO mapping");
    snprintf(path, sizeof(path), "/proc/%llu/mem", tid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        fail("read-only vDSO access");
    size_t length = high - low;
    char *bytes = malloc(length);
    if (!bytes || pread(fd, bytes, length, (off_t)low) != (ssize_t)length)
        fail("vDSO snapshot");
    close(fd);
    save(directory, name, bytes, length);
    free(bytes);
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: ete-direct-record TID DURATION AUX_SIZE EMPTY_DIRECTORY\n");
        return 2;
    }
    unsigned long long tid = number(argv[1]), size = number(argv[3]);
    char *end;
    double duration = strtod(argv[2], &end);
    if (!tid || tid > 2147483647 || *end || !isfinite(duration) || duration <= 0
        || duration > .03 || size < 1048576 || size > 67108864 || (size & (size - 1)))
        return 2;
    /* Only the repeated CPU0 route is exposed here. Never change target affinity. */
    char status_path[128], line[512];
    snprintf(status_path, sizeof(status_path), "/proc/%llu/status", tid);
    FILE *status = fopen(status_path, "r");
    if (!status)
        fail("target status");
    int pinned = 0;
    while (fgets(line, sizeof(line), status)) {
        if (sscanf(line, "Cpus_allowed_list: %127s", status_path) == 1)
            pinned = !strcmp(status_path, "0");
    }
    fclose(status);
    if (!pinned) {
        fprintf(stderr, "target must already be pinned to CPU0\n");
        return 2;
    }
    alarm(5); /* Kernel closes the event on process death; caller also has timeout. */
    save_vdso(tid, argv[4], "vdso-before.bin");
    struct perf_event_attr attr = {0};
    attr.type = read_uint("/sys/bus/event_source/devices/cs_etm/type", "%u");
    attr.size = sizeof(attr);
    attr.config = 1ULL << 14; /* Context ID, no timestamps/cycle packets/filter. */
    attr.config2 = read_uint("/sys/bus/event_source/devices/cs_etm/sinks/coresight-tmc-etr", "%x");
    attr.sample_period = 1;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.pinned = 1;
    attr.sample_type = PERF_SAMPLE_CPU;
    attr.sample_id_all = 1;
    event_fd = syscall(SYS_perf_event_open, &attr, (int)tid, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (event_fd < 0)
        fail("perf_event_open");
    size_t page = sysconf(_SC_PAGESIZE), data_size = 1048576;
    void *map = mmap(NULL, page + data_size, PROT_READ | PROT_WRITE, MAP_SHARED, event_fd, 0);
    if (map == MAP_FAILED)
        fail("mmap data");
    struct perf_event_mmap_page *metadata = map;
    metadata->aux_offset = page + data_size;
    metadata->aux_size = size;
    void *aux = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, event_fd, metadata->aux_offset);
    if (aux == MAP_FAILED)
        fail("mmap AUX");
    if (ioctl(event_fd, PERF_EVENT_IOC_ENABLE, 0))
        fail("enable");
    double started = monotonic_seconds();
    struct timespec delay = {0, (long)(duration * 1e9)};
    while (nanosleep(&delay, &delay)) {
        if (errno != EINTR)
            fail("nanosleep");
    }
    double sent = monotonic_seconds();
    if (ioctl(event_fd, PERF_EVENT_IOC_DISABLE, 0))
        fail("disable");
    double stopped = monotonic_seconds();
    save_vdso(tid, argv[4], "vdso-after.bin");
    __sync_synchronize();
    uint64_t head = metadata->data_head, tail = metadata->data_tail;
    uint64_t aux_head = metadata->aux_head, aux_tail = metadata->aux_tail;
    if (head < tail || aux_head < aux_tail || head - tail > data_size || aux_head - aux_tail > size)
        fail("ring bounds/loss");
    char *events = malloc(head - tail + 1), *bytes = malloc(aux_head - aux_tail + 1);
    if (!events || !bytes)
        fail("malloc");
    for (uint64_t i = tail; i < head; i++)
        events[i - tail] = ((char *)map)[page + i % data_size];
    for (uint64_t i = aux_tail; i < aux_head; i++)
        bytes[i - aux_tail] = ((char *)aux)[i % size];
    save(argv[4], "events.bin", events, head - tail);
    save(argv[4], "aux.bin", bytes, aux_head - aux_tail);
    save(argv[4], "attr.bin", &attr, sizeof(attr));
    char report[512];
    int length = snprintf(report, sizeof(report),
        "{\"cpu\":0,\"tid\":%llu,\"aux_bytes\":%llu,\"data_bytes\":%llu,"
        "\"window_seconds\":%.9f,\"disable_ack_seconds\":%.9f}\n",
        tid, (unsigned long long)(aux_head - aux_tail), (unsigned long long)(head - tail),
        sent - started, stopped - started);
    save(argv[4], "direct.json", report, length);
    munmap(aux, size);
    munmap(map, page + data_size);
    close(event_fd);
    event_fd = -1;
    free(events);
    free(bytes);
    puts("RESULT=direct_captured");
    return 0;
}
