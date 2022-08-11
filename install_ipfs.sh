#!/bin/bash

cd /home/$USER
wget https://dist.ipfs.io/go-ipfs/v0.14.0/go-ipfs_v0.14.0_linux-arm64.tar.gz
tar -xvzf go-ipfs_v0.14.0_linux-arm64.tar.gz
rm go-ipfs_v0.14.0_linux-arm64.tar.gz
cd go-ipfs
sudo bash install.sh
ipfs init

echo "[Unit]
Description=IPTS Daemon Service

[Service]
Type=simple
ExecStart=/usr/local/bin/ipfs daemon
User=$USER

[Install]
WantedBy=multi-user.target
" | sudo tee /etc/systemd/system/ipfs-daemon.service

sudo systemctl enable ipfs-daemon.service
sudo systemctl start ipfs-daemon.service
