# 📦 NyxOS Installation Guide

## System Requirements

### Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **RAM** | 4 GB | 8 GB+ (16 GB for local AI models) |
| **Disk** | 20 GB | 50 GB+ |
| **CPU** | 2 cores | 4+ cores |
| **GPU** | Not required | NVIDIA GPU for local Ollama models |

### Software

| Requirement | Version |
|------------|---------|
| **Python** | 3.12 or higher |
| **pip** | 23.0 or higher |
| **git** | 2.30 or higher |
| **OS** | Kali Linux (recommended), Debian 12+, Ubuntu 22.04+ |

---

## Installation Options

### Option A: VirtualBox ISO (Recommended for Beginners)

The easiest way to run NyxOS. Download the pre-built ISO and boot it in VirtualBox.

```bash
# 1. Download the NyxOS ISO
wget https://github.com/nyxos-project/nyxos/releases/latest/download/nyxos-latest-amd64.iso

# 2. Create a new VirtualBox VM
#    - Type: Linux / Debian (64-bit)
#    - RAM: 4096 MB minimum
#    - Disk: 20 GB minimum (dynamically allocated)
#    - Network: NAT or Bridged

# 3. Mount the ISO and boot
#    - Attach nyxos-latest-amd64.iso to the optical drive
#    - Start the VM
#    - Follow the installer (username, password, timezone)

# 4. After install, NyxOS starts automatically on login

