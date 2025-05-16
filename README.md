<div align="center">

<picture>
  <img alt="logo" src="/resources/images/application.png">
</picture>

</br>
</br>

**wireguard-linux**: lightweight desktop application for managing WireGuard tunnels.

<h3>

[Release Page](https://github.com/wirewizarddev/wireguard-linux/releases)

</h3>

</div>

### Install (Debian/Ubuntu)
```bash
wget https://github.com/wirewizarddev/wireguard-linux/releases/download/v1.0.2/wireguard-linux_1.0.2_amd64.deb

sudo dpkg -i wireguard-linux_1.0.2_amd64.deb
```

### Build from source:
```bash
make build
make install
make clear
```

### FAQ
- Why a binary file is ~**60** MB?
  * Because it's _Python_... Default libs ~**15**MB + PySide6 ~**40**MB + Source code ~**5**-**10**MB.
- How much _memory_ does the application consume?
  * The application itself uses **1**MB of RAM at startup.
- I get error in logs: _returned non-zero exit status 127_?
  * Most likely the problem is in the configuration file. They are different from the one on **windows**.
- How do i completely uninstall the application?
  * make uninstall

### Development
```bash
make sdk

python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

sudo LOCAL=ON venv/bin/python3.11 wireguard.py
```

### What i use
* Python 3.11
* Go 1.24.0
---
All Rights Reserved. "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.
