#!/bin/bash

echo "🚀 Installing AKIRA..."

# Update system
sudo apt update

# Install required system tools
echo "[+] Installing system dependencies..."
sudo apt install -y python3 python3-venv nmap nikto gobuster seclists dirb

# Setup project directory
PROJECT_DIR="$HOME/akira"

if [ ! -d "$PROJECT_DIR" ]; then
    echo "[+] Cloning AKIRA..."
    git clone https://github.com/0xprxdhx/akira.git "$PROJECT_DIR"
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
echo "[+] Creating command 'akira'..."
sudo bash -c "cat > /usr/local/bin/akira" <<EOL
#!/bin/bash
PROJECT_DIR="$PROJECT_DIR"
exec \$PROJECT_DIR/venv/bin/python \$PROJECT_DIR/main.py "\$@"
EOL

sudo chmod +x /usr/local/bin/akira

echo ""
echo "✅ AKIRA installed successfully!"
echo "👉 Run with: akira"
echo "👉 Or with root: sudo akira"
