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
wget https://github.com/wirewizard-dev/wireguard-linux/releases/download/v1.0.8/wireguard-linux_1.0.8_amd64.deb

sudo dpkg -i wireguard-linux_1.0.8_amd64.deb
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
- My dependency package has a different name. How do I install the deb package?
  * sudo dpkg --force-depends -i wireguard-linux_x.x.x_amd64.deb
- Why a binary file is ~**60** MB?
  * Because it's _Python_... Default libs ~**15** MB + PySide6 ~**40** MB + Source code ~**5**-**10** MB.
- How much _memory_ does the application consume?
  * The application itself uses **1** MB of RAM at startup.
- How do i completely uninstall the application?
  * make uninstall

### Development
```bash
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

make sdk
make dev
```

---
All Rights Reserved. "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.
