<div align="center">

<picture>
  <img alt="logo" src="/resources/images/application.png" width="70%" height="70%">
</picture>

**wireguard-linux**: lightweight desktop application for managing WireGuard tunnels with an interface inspired by the official [wireguard-windows](https://github.com/WireGuard/wireguard-windows).

</div>

### What i use
* Python 3.11
  * pyside6 6.9.0
  * pyinstaller 6.13.0
* Go 1.24.0

### Install (Debian/Ubuntu)
```bash
sudo apt install wireguard-tools git

git clone git@github.com:wirewizarddev/wireguard-linux.git
cd wireguard-linux

make install
```

### Development
```bash
make sdk

python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

sudo LOCAL=ON venv/bin/python3.11 wireguard.py
```