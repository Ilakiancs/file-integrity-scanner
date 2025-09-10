

# File Integrity Scanner

A real-time file integrity monitoring system with integrated malware detection capabilities.

## Features

- **File Integrity Monitoring** - Real-time detection of file changes, additions, and deletions
- **Malware Detection** - Machine learning-based analysis of executable files
- **Hash-based Verification** - SHA256 checksums for file integrity validation
- **VirusTotal Integration** - Online threat intelligence scanning
- **Command Line Interface** - Flexible monitoring configuration

## Installation

Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### File Integrity Monitoring
```bash
python antivirusXml.py -i /path/to/monitor -o alerts.log
```

### Malware Analysis
```bash
python Mal-detection.py suspicious_file.exe
```

### Train Detection Model
```bash
python Mal-detection-learning.py data.csv
```

## Components

- `antivirusXml.py` - Main file integrity monitoring engine
- `Mal-detection.py` - Malware classification system
- `Mal-detection-learning.py` - Model training module
- `virustotal.py` - VirusTotal API integration
- `data.csv` - Training dataset (138,000 samples)

## Requirements

- Python 3.x
- Windows PE file support for malware detection
- Internet connection for VirusTotal integration

## Author

Ilakian

## License

This project is for educational and security research purposes.



# file-integrity-scanner
