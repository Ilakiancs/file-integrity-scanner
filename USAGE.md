# Example Usage

## Basic File Monitoring
```bash
# Watch current directory for changes
python antivirusXml.py -i . -o my_alerts.log

# Watch a specific folder
python antivirusXml.py -i /path/to/folder -o alerts.txt
```

## Malware Detection
```bash
# Check if a file is malware
python Mal-detection.py sample.exe
```

## Training the Model (Advanced)
```bash
# Retrain the machine learning model with new data
python Mal-detection-learning.py
```

## VirusTotal Check
```bash
# Check a file using VirusTotal (needs API key)
python virustotal.py -m suspicious_file.exe
```

## Notes for Students
- Make sure to install requirements first: `pip install -r requirements.txt`
- The program creates log files to track what it finds
- Only Windows .exe files work with the ML detection
- You can stop the monitor with Ctrl+C
