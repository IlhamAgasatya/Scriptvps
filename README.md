# Scriptvps
#
apt update && apt upgrade -y && update-grub && sleep 2 && sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt upgrade && apt install -y bzip2 gzip coreutils screen curl unzip && wget -q https://github.com/IlhamAgasatya/Scriptvps/blob/fb9685a5fc7169dcc6e53477e9a23db40c879383/INSTALL/setup.sh && chmod +x setup.sh && ./setup.sh
