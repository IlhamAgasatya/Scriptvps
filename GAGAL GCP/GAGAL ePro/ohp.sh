#!/bin/bash
# Download File Ohp
unzip ohpserver-linux32.zip
chmod +x ohpserver
cp ohpserver /usr/local/bin/ohpserver
/bin/rm -rf ohpserver*

# Installing Service
# SSH OHP Port 8181
cat > /etc/systemd/system/ssh-ohp.service << END
[Unit]
Description=SSH OHP Redirection Service
Documentation=indo-ssh.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/ohpserver -port 8181 -proxy 127.0.0.1:3128 -tunnel 127.0.0.1:22
Restart=on-failure
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
END

# Dropbear OHP 8282
cat > /etc/systemd/system/dropbear-ohp.service << END
[Unit]]
Description=Dropbear OHP Redirection Service
Documentation=https://indo-ssh.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/ohpserver -port 8282 -proxy 127.0.0.1:3128 -tunnel 127.0.0.1:109
Restart=on-failure
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
END

# OpenVPN OHP 8383
cat > /etc/systemd/system/openvpn-ohp.service << END
[Unit]]
Description=OpenVPN OHP Redirection Service
Documentation=indo-ssh.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/ohpserver -port 8383 -proxy 127.0.0.1:3128 -tunnel 127.0.0.1:1194
Restart=on-failure
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload
systemctl enable ssh-ohp
systemctl restart ssh-ohp
systemctl enable dropbear-ohp
systemctl restart dropbear-ohp
systemctl enable openvpn-ohp
systemctl restart openvpn-ohp
#------------------------------
printf 'INSTALLATION COMPLETED !\n'
sleep 0.5
