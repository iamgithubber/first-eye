
# Install dependencies for ai-recon (macOS & Linux)

set -e

echo "[+] Detecting OS..."
OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
	echo "[+] Detected macOS. Installing with Homebrew."
	# System tools required (Homebrew)
	brew install subfinder assetfinder amass dnsx httpx naabu nuclei waybackurls gau jq
	# Optional tools (uncomment to install)
	# brew install subjack subzy massdns nmap whatweb wafw00f hakrawler katana gobuster
elif [ "$OS" = "Linux" ]; then
	echo "[+] Detected Linux. Installing with apt (Debian/Ubuntu)."
	sudo apt update
	sudo apt install -y jq nmap whatweb
	# The following tools may need to be installed manually or via go install:
	# subfinder, assetfinder, amass, dnsx, httpx, naabu, nuclei, waybackurls, gau, subjack, subzy, massdns, wafw00f, hakrawler, katana, gobuster
	echo "[!] For most recon tools, install Go (https://go.dev/doc/install) and then run:"
	echo '  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
	echo '  go install github.com/tomnomnom/assetfinder@latest'
	echo '  go install github.com/OWASP/Amass/v4/...@latest'
	echo '  go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest'
	echo '  go install github.com/projectdiscovery/httpx/cmd/httpx@latest'
	echo '  go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest'
	echo '  go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'
	echo '  go install github.com/tomnomnom/waybackurls@latest'
	echo '  go install github.com/lc/gau/v2/cmd/gau@latest'
	# Optional tools:
	echo '  go install github.com/haccer/subjack@latest'
	echo '  go install github.com/LukaSikic/subzy@latest'
	echo '  go install github.com/blechschmidt/massdns@latest'
	echo '  go install github.com/ffuf/ffuf@latest'
	echo '  go install github.com/hakluke/hakrawler@latest'
	echo '  go install github.com/projectdiscovery/katana/cmd/katana@latest'
	echo '  go install github.com/OJ/gobuster/v3@latest'
	echo '  pip3 install wafw00f'
else
	echo "[!] Unsupported OS: $OS. Please install dependencies manually."
	exit 1
fi

# For paramspider and arjun (Python tools)
pip3 install paramspider arjun

echo "[+] Dependency installation complete."

# Note: Some tools may require additional setup or configuration. See their official docs for details.
