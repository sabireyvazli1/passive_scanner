# passive_scanner
Dependencies:
1) Assetfinder 
▶ sudo apt install assetfinder 
2) Subfinder:
▶ sudo apt install subfinder
3) Amass:
▶ sudo apt install amass 
I have commented Amass code block in the source but if you want can just remove # and use amass too. But if you uncomment amass it will take way long time to finish.
4) Anew:
▶ sudo go install -v github.com/tomnomnom/anew@latest
▶ sudo cp /root/go/bin/anew /usr/local/bin
5) Filter-resolved:
▶ sudo go install github.com/tomnomnom/hacks/filter-resolved@latest
▶ sudo cp /root/go/bin/filter-resolved /usr/local/bin
6) Httporbe:
▶ sudo go install github.com/tomnomnom/httprobe@latest
▶ sudo cp /root/go/bin/httprobe /usr/local/bin
7) Dnsx:
▶ sudo go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
▶ sudo cp /root/go/bin/dnsx /usr/local/bin
8) Subzy:
▶ sudo go install -v github.com/LukaSikic/subzy@latest
▶ sudo cp /root/go/bin/subzy /usr/local/bin
9) Nmap:
▶ sudo apt install nmap 
10) Waybackurls:
▶ sudo go install github.com/tomnomnom/waybackurls@latest
▶ sudo cp /root/go/bin/waybackurls /usr/local/bin
11) Gowitness:
▶ sudo go install github.com/sensepost/gowitness@latest
▶ sudo cp /root/go/bin/gowitness /usr/local/bin