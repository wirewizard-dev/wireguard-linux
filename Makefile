build: sdk gui

gui:
	pyinstaller --name wireguard --onefile --windowed --add-binary "wirewizard.so:." wireguard.py

sdk:
	go build -buildmode=c-shared -o wirewizard.so wireguard.go && rm wirewizard.h

install:
	@sudo mkdir -p /opt/wirewizard/bin /opt/wirewizard/lib
	@sudo cp -r resources/ /opt/wirewizard/
	@sudo cp desktop/wireguard-linux.desktop /usr/share/applications/
	@sudo cp wirewizard.so /opt/wirewizard/lib/
	@sudo cp wireguard /opt/wirewizard/bin/

uninstall:
	@sudo rm -rf /opt/wirewizard
	@sudo rm /usr/share/applications/wireguard-linux.desktop

clear:
	rm wireguard.spec && rm -rf build/ dist/

dev:
	sudo LOCAL=ON venv/bin/python3.12 wireguard.py

memory:
	@PID=$$(ps aux | grep [w]ireguard | head -n 1 | awk '{print $$2}') && \
	ps -p $$PID -o rss= | awk '{printf "%.2f MB\n", $$1/1024}'

test:
	flake8 --config=config.cfg wireguard.py
