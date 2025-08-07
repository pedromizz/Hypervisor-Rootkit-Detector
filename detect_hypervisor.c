#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define MEM_DUMP_FILE "hv_mem_dump.bin"
#define DUMP_SIZE 4096*10

static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline void cpuid(uint32_t code, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    __asm__ __volatile__ ("cpuid" 
                          : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                          : "a"(code));
}

static inline uint64_t read_msr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

int detect_hypervisor_bit() {
    uint32_t a, b, c, d;
    cpuid(1, &a, &b, &c, &d);
    return (c >> 31) & 1;
}

void get_hypervisor_vendor(char *vendor) {
    uint32_t a, b, c, d;
    cpuid(0x40000000, &a, &b, &c, &d);
    memcpy(vendor, &b, 4);
    memcpy(vendor + 4, &c, 4);
    memcpy(vendor + 8, &d, 4);
    vendor[12] = '\0';
}

double measure_latency_cpuid() {
    uint64_t start, end;
    double avg = 0;
    for (int i = 0; i < 1000; i++) {
        start = rdtsc();
        uint32_t a,b,c,d;
        cpuid(0, &a, &b, &c, &d);
        end = rdtsc();
        avg += (end - start);
    }
    return avg / 1000.0;
}

double measure_timer_drift() {
    uint64_t t1 = rdtsc();
    usleep(200000);
    uint64_t t2 = rdtsc();
    return (double)(t2 - t1) / 200.0;
}

int detect_sidt_anomaly() {
    unsigned char idtr[10];
    __asm__ __volatile__("sidt %0" : "=m"(idtr));
    void *base = (void *)(*(unsigned long *)&idtr[2]);
    return ((uintptr_t)base < 0xFFF00000UL);
}

int detect_sgdt_anomaly() {
    unsigned char gdtr[10];
    __asm__ __volatile__("sgdt %0" : "=m"(gdtr));
    void *base = (void *)(*(unsigned long *)&gdtr[2]);
    return ((uintptr_t)base < 0xFFF00000UL);
}

int detect_sldt_anomaly() {
    unsigned short ldtr;
    __asm__ __volatile__("sldt %0" : "=m"(ldtr));
    return (ldtr != 0);
}

void check_msrs() {
    printf("MSR IA32_VMX_BASIC: 0x%llx\n", (unsigned long long)read_msr(0x480));
    printf("MSR IA32_FEATURE_CONTROL: 0x%llx\n", (unsigned long long)read_msr(0x3A));
}

void dump_physical_memory() {
    printf("Reading suspicious physical memory...\n");
    int fd = open("/dev/mem", O_RDONLY);
    if (fd < 0) {
        printf("Failed to open /dev/mem (requires root).\n");
        return;
    }
    unsigned char *buffer = malloc(DUMP_SIZE);
    if (!buffer) {
        close(fd);
        return;
    }
    if (lseek(fd, 0x100000, SEEK_SET) == (off_t)-1) {
        free(buffer);
        close(fd);
        return;
    }
    ssize_t r = read(fd, buffer, DUMP_SIZE);
    if (r > 0) {
        FILE *out = fopen(MEM_DUMP_FILE, "wb");
        if (out) {
            fwrite(buffer, 1, r, out);
            fclose(out);
            printf("Dump saved to %s (%ld bytes).\n", MEM_DUMP_FILE, (long)r);
        }
    }
    free(buffer);
    close(fd);
}

void scan_dump_for_signatures() {
    FILE *f = fopen(MEM_DUMP_FILE, "rb");
    if (!f) {
        printf("No dump found for analysis.\n");
        return;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    unsigned char *data = malloc(size);
    if (!data || fread(data, 1, size, f) != size) {
        printf("Error reading memory dump.\n");
        fclose(f);
        free(data);
        return;
    }
    fclose(f);

    const char *patterns[] = {"VMware", "KVMKVMKVM", "Microsoft Hv", "VBoxVBoxVBox", "BluePill"};
    int suspicious = 0;
    for (int i = 0; i < 5; i++) {
        if (memmem(data, size, patterns[i], strlen(patterns[i]))) {
            printf("Signature detected: %s\n", patterns[i]);
            suspicious++;
        }
    }
    if (!suspicious) printf("No known signatures found.\n");
    free(data);
}

int check_dmi_product_name() {
    FILE *f = fopen("/sys/class/dmi/id/product_name", "r");
    if (!f) return 0;

    char name[256] = {0};
    fgets(name, sizeof(name), f);
    fclose(f);

    if (strstr(name, "Virtual") || strstr(name, "VMware") || strstr(name, "KVM") || strstr(name, "VBox")) {
        printf("⚠ DMI Product Name suggests VM: %s", name);
        return 1;
    }

    return 0;
}

int main() {
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root.\n");
        return 1;
    }

    printf("=== Forensic Hypervisor Rootkit Detector ===\n");
    printf("Developed by miz992\n\n");

    int suspicion_level = 0;

    if (detect_hypervisor_bit()) {
        char vendor[13];
        get_hypervisor_vendor(vendor);
        printf("⚠ Hypervisor detected: %s\n", vendor);
        suspicion_level++;
        if (strstr(vendor, "VMware")) printf("→ VMware\n");
        else if (strstr(vendor, "KVM")) printf("→ KVM/QEMU\n");
        else if (strstr(vendor, "Microsoft Hv")) printf("→ Hyper-V\n");
        else if (strstr(vendor, "VBox")) printf("→ VirtualBox\n");
        else { printf("→ Uncommon vendor — possible stealth rootkit\n"); suspicion_level += 2; }
    } else {
        printf("No hypervisor bit set — may be stealth\n");
    }

    double latency = measure_latency_cpuid();
    printf("Average CPUID latency: %.2f cycles\n", latency);
    if (latency > 300) { printf("⚠ High overhead detected\n"); suspicion_level++; }

    double drift = measure_timer_drift();
    printf("Timer drift: %.2f cycles/ms\n", drift);
    if (drift < 1000 || drift > 10000000) { printf("⚠ Time manipulation suspected\n"); suspicion_level++; }

    if (detect_sidt_anomaly()) { printf("⚠ Suspicious IDT base\n"); suspicion_level++; }
    if (detect_sgdt_anomaly()) { printf("⚠ Suspicious GDT base\n"); suspicion_level++; }
    if (detect_sldt_anomaly()) { printf("⚠ Non-zero LDT\n"); suspicion_level++; }

    check_msrs();

    suspicion_level += check_dmi_product_name();

    dump_physical_memory();
    scan_dump_for_signatures();

    printf("\nSuspicion level: %d/10\n", suspicion_level);
    if (suspicion_level >= 5) printf("HIGH RISK — Possible stealth hypervisor rootkit.\n");
    else if (suspicion_level >= 2) printf("Moderate risk — signs of virtualization detected.\n");
    else printf("Low risk — nothing critical found.\n");

    printf("\n=== Analysis complete ===\n");
    return 0;
}
