# Hypervisor-Rootkit-Detector
Advanced Linux forensic tool for detecting hypervisors and virtualization-based rootkits using CPU fingerprinting and memory analysis.

Forensic Hypervisor Rootkit Detector
This tool is a low-level forensic utility designed for Linux systems to detect the presence of hypervisors, virtual machines, and stealth rootkits that operate at the hypervisor (ring-0) level. It combines hardware instruction-based techniques with memory analysis and system artifact inspection to provide a comprehensive assessment of virtualization or rootkit presence.

How It Works
Hypervisor Bit Detection:
The tool uses the CPUID instruction to check the hypervisor present bit, which indicates if the system is running inside a virtualized environment.

Vendor Identification:
By querying a special CPUID leaf (0x40000000), the tool extracts the hypervisor vendor signature string (e.g., VMware, KVM, Hyper-V, VirtualBox). This helps identify known virtualization platforms.

Latency and Timer Drift Measurement:
The tool measures the average latency of executing the CPUID instruction and timer drift using RDTSC and usleep(). Abnormal overhead or timing manipulation may indicate the presence of stealth hypervisors or time-hiding rootkits.

System Descriptor Table Checks:
It inspects the Interrupt Descriptor Table (IDT), Global Descriptor Table (GDT), and Local Descriptor Table (LDT) base addresses using SIDT, SGDT, and SLDT instructions. Anomalies in these tables can reveal kernel-level hooks or rootkits.

Model Specific Registers (MSRs):
Reads relevant MSRs (like IA32_VMX_BASIC and IA32_FEATURE_CONTROL) to gather information about CPU virtualization capabilities and control registers that could signal hypervisor presence.

Physical Memory Dump and Signature Scan:
The tool reads a section of physical memory via /dev/mem (requires root access) and scans the memory dump for known virtualization signatures such as "VMware", "KVMKVMKVM", "Microsoft Hv", "VBoxVBoxVBox", and "BluePill".

DMI Product Name Inspection:
It reads the DMI (Desktop Management Interface) product name from /sys/class/dmi/id/product_name to check for strings indicating virtual hardware platforms, adding another heuristic for VM detection.

Intended Use
This tool is designed for security researchers, incident responders, and system administrators who need to verify if a Linux system is running inside a VM or is compromised by stealth hypervisor rootkits. It provides detailed, low-level insight that is difficult to evade with simple VM detection tricks.

Requirements
Linux system with root privileges (required for physical memory dump)

GCC or compatible C compiler

Modern x86_64 CPU supporting CPUID, RDTSC, and related instructions

Limitations
Physical memory dumping requires root and may fail on some systems with strict kernel protections.

Detection heuristics rely on known signatures and timing thresholds; highly sophisticated stealth hypervisors could evade some checks.

Currently Linux-only and x86/x86_64 specific.

Conclusion
By combining multiple detection vectors—hardware instruction results, timing analysis, memory inspection, and system metadata—this tool provides a robust way to identify virtualization environments and stealth hypervisor rootkits on Linux hosts.
