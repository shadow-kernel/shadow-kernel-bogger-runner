#ifndef BOGGER_VMX_H
#define BOGGER_VMX_H

#include <stdint.h>
#include <stddef.h>

/* VMCS 32-bit control fields */
#define VMCS_PIN_BASED_CTLS         0x4000
#define VMCS_PRI_PROC_BASED_CTLS    0x4002
#define VMCS_SEC_PROC_BASED_CTLS    0x401E
#define VMCS_EXIT_CTLS              0x400C
#define VMCS_ENTRY_CTLS             0x4012
#define VMCS_EXCEPTION_BITMAP       0x4004
#define VMCS_MSR_BITMAP_ADDR        0x2004  /* 64-bit */

/* VMCS guest state fields */
#define VMCS_GUEST_CR0              0x6800
#define VMCS_GUEST_CR3              0x6802
#define VMCS_GUEST_CR4              0x6804
#define VMCS_GUEST_DR7              0x681A
#define VMCS_GUEST_RSP              0x681C
#define VMCS_GUEST_RIP              0x681E
#define VMCS_GUEST_RFLAGS           0x6820
#define VMCS_GUEST_CS_SEL           0x0802
#define VMCS_GUEST_CS_BASE          0x6808
#define VMCS_GUEST_CS_LIMIT         0x4800
#define VMCS_GUEST_CS_AR            0x4816
#define VMCS_GUEST_SS_SEL           0x0804
#define VMCS_GUEST_DS_SEL           0x0806
#define VMCS_GUEST_ES_SEL           0x0800
#define VMCS_GUEST_FS_SEL           0x0808
#define VMCS_GUEST_GS_SEL           0x080A
#define VMCS_GUEST_LDTR_SEL         0x080C
#define VMCS_GUEST_TR_SEL           0x080E
#define VMCS_GUEST_GDTR_BASE        0x6816
#define VMCS_GUEST_IDTR_BASE        0x6818
#define VMCS_GUEST_GDTR_LIMIT       0x4810
#define VMCS_GUEST_IDTR_LIMIT       0x4812
#define VMCS_GUEST_IA32_EFER        0x2806
#define VMCS_GUEST_ACTIVITY_STATE   0x4826
#define VMCS_GUEST_INTERRUPTIBILITY 0x4824
#define VMCS_GUEST_VMCS_LINK_PTR    0x2800

/* VMCS host state fields */
#define VMCS_HOST_CR0               0x6C00
#define VMCS_HOST_CR3               0x6C02
#define VMCS_HOST_CR4               0x6C04
#define VMCS_HOST_RSP               0x6C14
#define VMCS_HOST_RIP               0x6C16
#define VMCS_HOST_CS_SEL            0x0C02
#define VMCS_HOST_SS_SEL            0x0C04
#define VMCS_HOST_DS_SEL            0x0C06
#define VMCS_HOST_ES_SEL            0x0C00
#define VMCS_HOST_FS_SEL            0x0C08
#define VMCS_HOST_GS_SEL            0x0C0A
#define VMCS_HOST_TR_SEL            0x0C0C
#define VMCS_HOST_IA32_EFER         0x2C02
#define VMCS_HOST_GDTR_BASE         0x6C0C
#define VMCS_HOST_IDTR_BASE         0x6C0E

/* VM exit reason field */
#define VMCS_EXIT_REASON            0x4402
#define VMCS_EXIT_QUALIFICATION     0x6400
#define VMCS_EXIT_INSTR_LEN         0x440C
#define VMCS_GUEST_PHYS_ADDR        0x2400

/* VMCS TSC offset */
#define VMCS_TSC_OFFSET             0x2010

/* VM exit reasons */
#define VMX_EXIT_EXCEPTION_NMI      0
#define VMX_EXIT_CPUID              10
#define VMX_EXIT_HLT                12
#define VMX_EXIT_RDMSR              31
#define VMX_EXIT_WRMSR              32
#define VMX_EXIT_VMCALL             18
#define VMX_EXIT_EPT_VIOLATION      48

/* MSRs */
#define MSR_IA32_VMX_BASIC          0x480
#define MSR_IA32_FEATURE_CONTROL    0x3A
#define MSR_IA32_EFER               0xC0000080
#define MSR_IA32_SYSENTER_CS        0x174
#define MSR_IA32_SYSENTER_ESP       0x175
#define MSR_IA32_SYSENTER_EIP       0x176

/* IA32_EFER bits */
#define EFER_LME                    (1ULL << 8)
#define EFER_LMA                    (1ULL << 10)

/* CR4 bits */
#define CR4_VMXE                    (1UL << 13)

/* VMCS revision ID location in IA32_VMX_BASIC */
#define VMX_BASIC_REVISION_MASK     0x7FFFFFFF

/* Primary processor-based VM-execution control bits */
#define PRI_PROC_HLT_EXITING        (1U << 7)
#define PRI_PROC_RDTSC_EXITING      (1U << 12)
#define PRI_PROC_RDPMC_EXITING      (1U << 11)
#define PRI_PROC_MSR_BITMAPS        (1U << 28)
#define PRI_PROC_SECONDARY_CTLS     (1U << 31)

/* Secondary processor-based VM-execution control bits */
#define SEC_PROC_ENABLE_EPT         (1U << 1)
#define SEC_PROC_RDTSCP             (1U << 3)
#define SEC_PROC_UNRESTRICTED_GUEST (1U << 7)
#define SEC_PROC_INVPCID            (1U << 12)

/* VM-exit control bits */
#define EXIT_CTL_HOST_ADDR_SPACE    (1U << 9)
#define EXIT_CTL_ACK_INTR_ON_EXIT   (1U << 15)

/* VM-entry control bits */
#define ENTRY_CTL_IA32E_GUEST       (1U << 9)

typedef struct {
    uint32_t revision_id;
    uint8_t  data[4092];
} __attribute__((packed, aligned(4096))) bogger_vmcs_region_t;

typedef struct {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp;
    uint64_t r8,  r9,  r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip, rsp, rflags;
    uint64_t cr0, cr3, cr4;
} bogger_guest_state_t;

/* MSR intercept bitmap — 4 KB, 4-page aligned */
extern uint8_t g_msr_bitmap[4096];

/* Host stack for VM-exit handler */
#define BOGGER_HOST_STACK_SIZE 4096
extern uint8_t g_host_stack[BOGGER_HOST_STACK_SIZE];

/* Function prototypes */
int  bogger_vmx_check_support(void);
int  bogger_vmx_enable(void);
int  bogger_vmxon(bogger_vmcs_region_t *vmxon_region);
int  bogger_setup_vmcs(bogger_vmcs_region_t *vmcs, uint64_t guest_rip, uint64_t guest_rsp);
int  bogger_vmlaunch(void);
void bogger_vmexit_handler(bogger_guest_state_t *guest);
void bogger_advance_rip(bogger_guest_state_t *guest, uint32_t bytes);

static inline uint64_t bogger_rdmsr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void bogger_wrmsr(uint32_t msr, uint64_t val) {
    __asm__ volatile("wrmsr" :: "c"(msr), "a"((uint32_t)val), "d"((uint32_t)(val >> 32)));
}

static inline uint64_t bogger_read_cr0(void) {
    uint64_t v; __asm__ volatile("mov %%cr0, %0" : "=r"(v)); return v;
}
static inline uint64_t bogger_read_cr3(void) {
    uint64_t v; __asm__ volatile("mov %%cr3, %0" : "=r"(v)); return v;
}
static inline uint64_t bogger_read_cr4(void) {
    uint64_t v; __asm__ volatile("mov %%cr4, %0" : "=r"(v)); return v;
}
static inline void bogger_write_cr4(uint64_t v) {
    __asm__ volatile("mov %0, %%cr4" :: "r"(v));
}

static inline uint64_t bogger_vmread(uint64_t field) {
    uint64_t v;
    __asm__ volatile("vmread %1, %0" : "=r"(v) : "r"(field) : "cc");
    return v;
}
static inline void bogger_vmwrite(uint64_t field, uint64_t val) {
    __asm__ volatile("vmwrite %1, %0" :: "r"(field), "r"(val) : "cc");
}

/* Read a segment selector from the CPU */
static inline uint16_t bogger_read_cs(void) {
    uint16_t v; __asm__ volatile("mov %%cs, %0" : "=r"(v)); return v;
}
static inline uint16_t bogger_read_ss(void) {
    uint16_t v; __asm__ volatile("mov %%ss, %0" : "=r"(v)); return v;
}
static inline uint16_t bogger_read_ds(void) {
    uint16_t v; __asm__ volatile("mov %%ds, %0" : "=r"(v)); return v;
}
static inline uint16_t bogger_read_es(void) {
    uint16_t v; __asm__ volatile("mov %%es, %0" : "=r"(v)); return v;
}
static inline uint16_t bogger_read_fs(void) {
    uint16_t v; __asm__ volatile("mov %%fs, %0" : "=r"(v)); return v;
}
static inline uint16_t bogger_read_gs(void) {
    uint16_t v; __asm__ volatile("mov %%gs, %0" : "=r"(v)); return v;
}
static inline uint16_t bogger_read_tr(void) {
    uint16_t v; __asm__ volatile("str %0" : "=r"(v)); return v;
}

/* Read GDTR / IDTR base */
static inline uint64_t bogger_read_gdtr_base(void) {
    struct { uint16_t limit; uint64_t base; } __attribute__((packed)) desc;
    __asm__ volatile("sgdt %0" : "=m"(desc));
    return desc.base;
}
static inline uint64_t bogger_read_idtr_base(void) {
    struct { uint16_t limit; uint64_t base; } __attribute__((packed)) desc;
    __asm__ volatile("sidt %0" : "=m"(desc));
    return desc.base;
}

#endif /* BOGGER_VMX_H */
