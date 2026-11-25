# LSB Image Steganography in C

Hide text inside a 24-bit BMP using the least significant bit of each pixel byte.

    make                # builds ./steg
    make test           # encode + decode round trip
    ./steg encode samples/input.bmp encoded.bmp "your secret"
    ./steg decode encoded.bmp
    ./steg info samples/input.bmp
    ./steg              # interactive menu (Encode / Decode / Exit)

Open `index.html` in a browser for the project site and live demo.

## Improvements over the classroom version
- Reads the real pixel-data offset from the header (not a fixed 54 bytes)
- Skips row padding; validates 24-bit, uncompressed, truncated files
- Whole file read once, modified in memory, written once (no per-byte fread/fwrite)
- Capacity check, no fixed 200-char buffer, no scanf overflow
- "STG1" marker + length + FNV-1a checksum detects missing or damaged data
- CLI mode plus the original menu; every error path frees memory and closes files
