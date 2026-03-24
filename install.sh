#!/bin/bash

echo "🚀 Installing rexa..."

# Update system
sudo apt update

# Install required system tools
echo "[+] Installing system dependencies..."
sudo apt install -y python3 python3-venv nmap nikto gobuster seclists dirb

# Setup project directory
PROJECT_DIR="$HOME/rexa"

if [ ! -d "$PROJECT_DIR" ]; then
    echo "[+] Cloning rexa..."
    git clone https://github.com/0xprxdhx/rexa.git "$PROJECT_DIR"
fi

cd "$PROJECT_DIR"

# Create virtual environment
echo "[+] Setting up Python environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create launcher
echo "[+] Creating command 'rexa'..."
sudo bash -c "cat > /usr/local/bin/rexa" <<EOL
#!/bin/bash
PROJECT_DIR="$PROJECT_DIR"
exec \$PROJECT_DIR/venv/bin/python \$PROJECT_DIR/main.py "\$@"
EOL

sudo chmod +x /usr/local/bin/rexa

echo ""
echo "✅ rexa installed successfully!"
echo "👉 Run with: rexa"
echo "👉 Or with root: sudo rexa"
