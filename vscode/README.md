# VulnBuster UI VSCode Extension

This extension integrates VulnBuster's scan engine and reporting into VSCode.

## Features
- Start/Stop scans from the command palette
- View scan status in the status bar
- Preview latest report in a VSCode tab

## Installation
1. Open the `vscode/` folder in VSCode.
2. Run `npm install` to install dependencies.
3. Press `F5` to launch the extension in a new Extension Development Host window.

## Usage
- The extension activates automatically in any workspace containing a `.vulnbuster` file.
- Use the Command Palette (`Ctrl+Shift+P`) and search for:
  - `VulnBuster: Start Scan`
  - `VulnBuster: Stop Scan`
  - `VulnBuster: View Report`
- The status bar will show scan status.

## Requirements
- VulnBuster Flask API (`plugin_interface.py`) must be running on `http://localhost:5000`.

## Troubleshooting
- If the status bar shows `API Offline`, ensure the Flask server is running. 