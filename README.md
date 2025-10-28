# Web App Vulnerability Scanner (Learning Project)

A Flask-based web vulnerability scanner that detects SQL Injection and XSS vulnerabilities.

## Features
- Automated web crawling
- SQL injection detection
- XSS detection
- Real-time scan progress updates
- Detailed vulnerability reports

## Installation

### Option 1: Using Docker
```bash
git clone https://github.com/Roshan-Sajja/webapp-vuln-scanner.git
cd webapp-vuln-scanner

docker build -t webapp-vuln-scanner .

docker run -p 5000:5000 webapp-vuln-scanner
```
Then open your browser to **http://localhost:5000**

### Option 2: Manual installation

```bash
git clone https://github.com/Roshan-Sajja/webapp-vuln-scanner.git
cd webapp-vuln-scanner

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

python app.py
```
Then open your browser to **http://localhost:5000**


### Recommended Test Targets

Safe, intentional vulnerable sites for testing

**http://testphp.vulnweb.com/**

Ethical use only: Scanning third-party systems without written permission may be illegal. Use DVWA, Mutillidae, WebGoat, or your own apps for testing.

## Troubleshooting

### Docker Issues
**Port already in use: **
```bash
docker run -p 8080:5000 webapp-vuln-scanner
# Access at http://localhost:8080
```

### Manual Installation Issues
**Module not found:**
```bash
pip install -r requirements.txt --upgrade
```

**Permission errors on Linux:**
```bash
sudo apt-get install python3-dev libxml2-dev libxslt1-dev
```

**Port 5000 in use:**
Edit `app.py` and change:
```python
app.run(debug=True, port=5001)
```

## Disclaimer

This tool is for educational purposes only. 
**Remember**: Ethical hacking requires explicit permission. Test responsibly.
