# Linux compatibility matrix

| Environment | Installer path | GUI/fixture assessment | Live network scope | Status |
|---|---|---:|---|---|
| Kali Linux 2026.1 on WSL2, x86_64 | apt-get, project venv | Verified | TCP/external checks; Layer-2/wireless/privileged limits apply | Verified in this environment |
| Debian/Ubuntu, x86_64 | apt-get, project venv | Installer logic implemented; fresh host not exercised here | Depends on installed tools and permissions | Not independently validated |
| Fedora/RHEL-compatible | dnf/yum, project venv | Installer logic implemented; fresh host not exercised here | Depends on installed tools and permissions | Not independently validated |
| Arch Linux | pacman, project venv | Installer logic implemented; fresh host not exercised here | Depends on installed tools and permissions | Not independently validated |
| openSUSE | zypper, project venv | Installer logic implemented; fresh host not exercised here | Depends on installed tools and permissions | Not independently validated |
| arm64 Linux | Native Python path; local Ollama URL is architecture-dependent | Not independently validated here | Depends on tools and access | Not validated |

The installer reports unsupported package managers instead of claiming compatibility. Native Linux sensors are required for wireless, Layer-2, and some internal capabilities.
