#!/bin/bash
# One-click setup script for Photo Share app on Ubuntu/Debian VPS

set -e

echo "=========================================="
echo "Photo Share App - VPS Setup Script"
echo "=========================================="

# Update system packages
echo "[1/7] Updating system packages..."
sudo apt-get update -y

# Install Python and pip
echo "[2/7] Installing Python and dependencies..."
sudo apt-get install -y python3 python3-pip python3-venv git

# Create app directory
APP_DIR="/opt/photoshare"
echo "[3/7] Creating application directory at $APP_DIR..."
sudo mkdir -p $APP_DIR
sudo chown $USER:$USER $APP_DIR

# Clone or update the repository
REPO_URL="https://github.com/rahuja123/image_sharing.git"
echo "[4/7] Cloning repository..."
if [ -d "$APP_DIR/.git" ]; then
    cd $APP_DIR
    git pull origin main
else
    git clone $REPO_URL $APP_DIR
    cd $APP_DIR
fi

# Create virtual environment
echo "[5/7] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "[6/7] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Generate encryption key if not set
if [ -z "$ENCRYPTION_KEY" ]; then
    echo "[INFO] Generating new encryption key..."
    ENCRYPTION_KEY=$(python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())")
    echo "ENCRYPTION_KEY=$ENCRYPTION_KEY" | sudo tee /etc/photoshare.env > /dev/null
    echo "[INFO] Encryption key saved to /etc/photoshare.env"
fi

# Create systemd service
echo "[7/7] Creating systemd service..."
sudo tee /etc/systemd/system/photoshare.service > /dev/null << 'EOF'
[Unit]
Description=Photo Share - Disappearing Photo Sharing App
After=network.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/photoshare
EnvironmentFile=-/etc/photoshare.env
ExecStart=/opt/photoshare/venv/bin/python app.py
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable photoshare
sudo systemctl restart photoshare

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "The app is now running on port 5050"
echo "Access it at: http://YOUR_VPS_IP:5050"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status photoshare   - Check app status"
echo "  sudo systemctl restart photoshare  - Restart the app"
echo "  sudo journalctl -u photoshare -f   - View logs"
echo ""
echo "IMPORTANT: Make sure port 5050 is open in your AWS Security Group!"
echo ""
