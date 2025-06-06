<div align="center">

<picture>
  <img alt="logo" src="/resources/images/application.png">
</picture>

</br>
</br>

**wireguard-linux**: lightweight desktop application for managing WireGuard tunnels.

</div>

### Dependencies
* wireguard-tools

### Install
```bash
wget https://github.com/wirewizarddev/wireguard-linux/releases/download/v1.0.6/wireguard-linux_1.0.6_amd64.deb

sudo dpkg -i wireguard-linux_1.0.6_amd64.deb
```

### Build from source
For a successful build, you must have:
- make
- golang
- python, pip
```bash
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

make build

make install

make clear

deactivate
```

### FAQ
- Why a binary file is ~**60** MB?
  * Because it's _Python_... Default libs ~**15** MB + PySide6 ~**40** MB + Source code ~**5**-**10** MB.
- How much _memory_ does the application consume?
  * The application itself uses **1** MB of RAM at startup.
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

---
All Rights Reserved. "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.
