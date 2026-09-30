# LNK Parser 🔍

A web-based analyzer for Windows .LNK (shortcut) files, designed to extract command-line arguments and detect malicious patterns in shortcut files.

**Live Demo:** [https://yourusername.github.io/lnk-parser](https://yourusername.github.io/lnk-parser)

## Features

- 🎯 **Command Line Extraction** - Automatically extracts command-line arguments from LNK files
- ⚠️ **Malicious Pattern Detection** - Identifies suspicious indicators:
  - PowerShell encoding/obfuscation
  - Command injection patterns
  - Suspicious executables (rundll32, msiexec, certutil, etc.)
  - Temporary directory access
  - Encoded payloads

- 📊 **Risk Assessment** - Categorizes threats as HIGH, MEDIUM, or LOW risk
- 📁 **Metadata Extraction** - Shows file attributes, timestamps, paths, and more
- 🖱️ **Drag & Drop Upload** - Easy file upload with drag and drop support

## How to Use

1. Visit the [Live Demo](https://yourusername.github.io/lnk-parser)
2. Drag and drop a `.LNK` file or click to upload
3. Analyze the extracted data and check for suspicious indicators

## What Gets Extracted

- Command-line arguments
- Working directory
- File paths (relative and absolute)
- Icon location
- File creation/access/modification timestamps
- Link flags and file attributes
- Environment variables (if present)

## Risk Indicators

### HIGH Risk 🔴
- PowerShell with encoding or bypass flags
- CMD running PowerShell with hidden execution
- Script engines (wscript, cscript)
- System tools: rundll32, msiexec, certutil, regsvr32, bitsadmin
- Temp directory execution
- Hidden NoProfile execution

### MEDIUM Risk 🟡
- PowerShell execution
- CMD execution
- Setup executables
- URLs in command line
- Long encoded strings

### LOW Risk 🟢
- Standard applications
- No suspicious patterns detected

## Installation (Local Development)

```bash
# Clone the repository
git clone https://github.com/yourusername/lnk-parser.git
cd lnk-parser

# Serve locally (Python 3)
python -m http.server 8000

# Or use Node.js http-server
npx http-server
```

Then visit `http://localhost:8000`

## Technical Details

### LNK File Format
The parser reads the Windows .LNK (Shell Link) file format:
- **Header** (76 bytes) - Contains signature, timestamps, file size, and flags
- **LinkInfo** (optional) - Contains file path information
- **String Data** - Contains command-line arguments and paths
- **Extra Data Blocks** - Console data, environment variables, and more

### Parsing Strategy
1. Validates LNK file signature (0x4C)
2. Extracts header information (timestamps, attributes, flags)
3. Parses LinkInfo structure for file paths
4. Extracts string data for command-line arguments
5. Analyzes extra data blocks for environment variables
6. Detects suspicious patterns and assigns risk level

## Security Considerations

⚠️ **Important:** This tool runs entirely in your browser. No files are uploaded to any server.
- All analysis happens locally in JavaScript
- Your files are never stored or transmitted
- Use this tool to analyze potentially malicious files safely

## Supported Platforms

- Windows 7+
- Modern browsers (Chrome, Firefox, Safari, Edge)

## LNK File Sources

- Windows shortcut files (`.lnk`)
- Microsoft Office recent items
- Windows Start Menu shortcuts
- Desktop shortcuts
- Any Windows shell link files

## Troubleshooting

### "Invalid LNK file signature"
- The file is not a valid Windows LNK file
- Try with a different LNK file

### "File is too small"
- Corrupted or incomplete LNK file
- Try re-exporting or copying the shortcut

## Contributing

Found a bug or want to improve the parser? Open an issue or submit a pull request!

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is for security research and threat analysis purposes only. Users are responsible for complying with all applicable laws and regulations when analyzing files.

---

**Made with ❤️ for cybersecurity professionals and researchers**
