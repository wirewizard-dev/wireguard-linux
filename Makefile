build: sdk gui

gui:
	pyinstaller --name wireguard --onefile --windowed --add-binary "wirewizard.so:." wireguard.py

sdk:
	go build -buildmode=c-shared -o wirewizard.so wireguard.go && rm wirewizard.h

clear:
	rm wireguard.spec && rm -rf build/ dist/ wirewizard.so

install:
	@sudo mkdir -p /opt/wirewizard/bin /opt/wirewizard/lib /opt/wirewizard/resources
	@sudo cp -r resources/icons/ /opt/wirewizard/resources/
	@sudo cp wirewizard.so /opt/wirewizard/lib/
	chmod +x dist/wireguard
	@sudo cp dist/wireguard /opt/wirewizard/bin/
	@sudo cp deb/desktop/wireguard-linux.desktop /usr/share/applications/
	@sudo cp deb/policy/org.freedesktop.wirewizard.policy /usr/share/polkit-1/actions/

uninstall:
	@sudo rm -rf /opt/wirewizard
	@sudo rm /usr/share/applications/wireguard-linux.desktop
	@sudo rm /usr/share/polkit-1/actions/org.freedesktop.wirewizard.policy

dev:
	sudo LOCAL=ON venv/bin/python3.11 wireguard.py

memory:
	@PID=$$(ps aux | grep [w]ireguard | head -n 1 | awk '{print $$2}') && \
	ps -p $$PID -o rss= | awk '{printf "%.2f MB\n", $$1/1024}'

test:
	flake8 --config=config.cfg wireguard.py
