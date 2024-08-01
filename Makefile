OS=					$$(uname -o)

.PHONY: depends
depends:
	@echo "Install Dependencies"
	@if [ -e /etc/debian_version ]; then\
		DEBIAN_FRONTEND=noninteractive apt install -y git openvpn python3-pip libcurl4;\
	elif [ "${OS}" = "FreeBSD" ]; then\
		pkg install -y git-lite python311 py311-pip py311-pycurl;\
	fi

.PHONY: install
install:
	@pip install -Ur requirements.txt
	@mkdir -p ~/.local/bin
	@cp rir-ip-info.py ~/.local/bin/rir-ip-info
	@chmod +x ~/.local/bin/rir-ip-info

.PHONY: uninstall
uninstall:
	rm ~/.local/bin/rir-ip-info

help:
	@echo "    install"
	@echo "        Installs rir-ip-info"
	@echo "    uninstall"
	@echo "        Removes rir-ip-info"
	@echo "    depends"
	@echo "        Installs rir-ip-info dependencies"