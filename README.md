# Deep Freeze PowerShell Scripts

> [!CAUTION]
> **Disclaimer:** Use these scripts at your own risk. I am not responsible for any damage, loss of data, or property damage resulting from their use.

---

## Scripts Overview

### 1. `DeepFreezeSetup.ps1`
Designed for library or public lab environments to automate machine provisioning.
Will reboot the system and uses task scheduler for Deep Freeze after booting fresh user profile.

#### **Core Features**
- [x] Creates a new local user account
- [x] Configures Windows system settings
- [x] Installs Deep Freeze
- [ ] Optionally runs removal script (if included)

> [!IMPORTANT]
> Review configuration, read through the script and test in a **non-production environment** before mass deployment.

### 2. `DeepFreezeRemoval.ps1`
A standalone utility to uninstall Deep Freeze from the machine.

<details>
<summary>⚠️ <b>Maintenance & Support (Click to expand)</b></summary>

This script is **not actively maintained** and may not work with newer versions of Deep Freeze. It is highly recommended to contact [Faronics](https://www.faronics.com) for the official, up-to-date removal tool.
</details>

---

## 🛠 Prerequisites & Requirements

| Requirement | Details |
| :--- | :--- |
| **OS** | Windows 10/11 with PowerShell 5.1+ |
| **Permissions** | Full Administrative Privileges |
| **Software** | Deep Freeze Installer (.exe/msi) |
| **State** | Machine must be **Thawed** for removal |

