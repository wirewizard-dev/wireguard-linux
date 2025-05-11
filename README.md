### DEVELOPMENT
```bash
make sdk

python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

sudo LOCAL=ON venv/bin/python3.12 wireguard.py
```