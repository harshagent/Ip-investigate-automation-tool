#!/bin/bash

# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip python3-venv -y

# Install firewall and allow SSH and HTTP
sudo apt install ufw -y
sudo ufw allow ssh
sudo ufw allow 5000
sudo ufw --force enable

# Create directory for the app
sudo mkdir -p /var/www/html/ip-investigate
sudo chown -R $USER:$USER /var/www/html/ip-investigate

# Create virtual environment
cd /var/www/html/ip-investigate
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Deactivate venv
deactivate

# Create systemd service file
sudo tee /etc/systemd/system/ip-investigate.service > /dev/null <<EOF
[Unit]
Description=IP Investigate Flask App
After=network.target

[Service]
User=$USER
Group=$USER
WorkingDirectory=/var/www/html/ip-investigate
Environment="PATH=/var/www/html/ip-investigate/venv/bin"
Environment="VT_API_KEY=your_virustotal_api_key"
Environment="ABUSE_API_KEY=your_abuseipdb_api_key"
ExecStart=/var/www/html/ip-investigate/venv/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable ip-investigate

echo "Setup complete. Now upload your project files to /var/www/html/ip-investigate"
echo "Then run: sudo systemctl start ip-investigate"
echo "Check status: sudo systemctl status ip-investigate"
echo "The app will be available at http://your_vps_ip:5000"
