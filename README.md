# PasswordCracker

A GUI-based tool to crack passwords for ZIP, RAR, 7z, and PDF files using dictionary or brute-force attacks.

## Features
- Supports **ZIP, RAR, 7z, and PDF** files.
- Two attack modes:
  - **Dictionary Attack**: Test passwords from a wordlist.
  - **Brute Force Attack**: Generate password combinations using customizable character sets.
- Multi-threaded brute-force for faster cracking.
- Password strength analysis and dictionary analysis tools.
- Dark/Light theme support.

## Installation

### Prerequisites
- Python 3.6 or higher
- System dependencies:
  - **UnRAR** (for RAR support):
    - **Windows**: Download [UnRAR](https://www.rarlab.com/rar_add.htm) and set the path in `passwordcrack.py` (line 13: `rarfile.UNRAR_TOOL = r"E:\\UNRAR\\unrar.exe"`).
    - **Linux**: Install via `sudo apt-get install unrar`.

### Install Python Packages
1. Clone this repository or download the script.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
