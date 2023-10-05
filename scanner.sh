#!/bin/bash

url=$1

if [ "$#" -eq 0 ]; then
        echo "Usage: bash scanner.sh url"
else

        echo "------------------------------------------------------------"
        echo " "
        echo "                     CS402 Web Recon                        "
        echo " "
        echo "------------------------------------------------------------"

        if [ ! -d "$url" ];then
                mkdir $url
        fi
        if [ ! -d "$url/recon" ];then
                mkdir $url/recon
                echo "$1" > $url/recon/$1.txt
        fi
        if [ ! -d "$url/recon/gowitness" ];then
                mkdir $url/recon/gowitness
        fi
        if [ ! -d "$url/recon/scans" ];then
                mkdir $url/recon/scans
        fi
        if [ ! -d "$url/recon/httprobe" ];then
                mkdir $url/recon/httprobe
        fi
        if [ ! -d "$url/recon/potential_takeovers" ];then
                mkdir $url/recon/potential_takeovers
        fi
        if [ ! -d "$url/recon/wayback" ];then
                mkdir $url/recon/wayback
        fi
        if [ ! -d "$url/recon/wayback/params" ];then
                mkdir $url/recon/wayback/params
        fi
        if [ ! -d "$url/recon/wayback/extensions" ];then
                mkdir $url/recon/wayback/extensions
        fi
        if [ ! -f "$url/recon/httprobe/alive.txt" ];then
                touch $url/recon/httprobe/alive.txt
        fi
        if [ ! -f "$url/recon/final.txt" ];then
                touch $url/recon/final.txt
        fi
        if [ ! -d "$url/recon/dnsrecords" ];then
                mkdir $url/recon/dnsrecords
        fi

        echo "*** Harvesting subdomains with ASSETFINDER ***"
        assetfinder --subs-only $url >> $url/recon/assets.txt
        cat $url/recon/assets.txt | filter-resolved | grep $1 >> $url/recon/final.txt
        rm $url/recon/assets.txt
        echo "-----------------------------------------------"

        echo "*** Harvesting subdomains with SUBFINDER ***"
        cat $url/recon/$1.txt | subfinder >> $url/recon/sub.txt &
        cat $url/recon/sub.txt | filter-resolved | grep $1 | anew $url/recon/final.txt
        rm $url/recon/sub.txt
        echo "-----------------------------------------------"

        #echo "*** Harvesting subdomains with AMASS ***"
        #amass enum -passive -d $url >> $url/recon/f.txt
        #sort -u $url/recon/f.txt | anew $url/recon/final.txt
        #rm $url/recon/f.txt
        #echo "-----------------------------------------------"

        echo "*** Probing for alive domains with HTTPROBE ***"
        cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 -p https:8443 | sed 's/https\?:\/\///' | tr -d ':348' >> $url/recon/httprobe/a.txt
        cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 -p https:8443 | sed 's/https\?:\/\///' >> $url/recon/httprobe/with_port.txt
        cat $url/recon/final.txt | sort -u | httprobe -s -p http:80 -p http:81 -p http:82 -p http:8080 | sed 's/http\?:\/\///' | tr -d ':0128' >> $url/recon/httprobe/b.txt
        cat $url/recon/final.txt | sort -u | httprobe -s -p http:80 -p http:81 -p http:82 -p http:8080 | sed 's/http\?:\/\///' | anew $url/recon/httprobe/with_port.txt
        sort -u $url/recon/httprobe/a.txt > $url/recon/httprobe/alive.txt
        sort -u $url/recon/httprobe/b.txt | anew $url/recon/httprobe/alive.txt
        rm $url/recon/httprobe/b.txt
        rm $url/recon/httprobe/a.txt
        echo "----------------------------------------------"

        echo "*** Checking for DNS records with DNSX ***"
        cat $url/recon/httprobe/alive.txt | dnsx -silent -a -aaaa -cname -mx -resp | anew $url/recon/dnsrecords/$1_dnsrecords.txt
        echo "----------------------------------------------"

        echo "*** Checking for possible subdomain takeover with SUBZY ***"
        if [ ! -f "$url/recon/potential_takeovers/potential_takeovers.txt" ];then
                touch $url/recon/potential_takeovers/potential_takeovers.txt
        fi

        subzy run --targets $url/recon/httprobe/alive.txt >> $url/recon/potential_takeovers/potential_takeovers.txt
        echo "----------------------------------------------"

        echo "*** Scanning for open ports with NMAP ***"
        nmap -iL $url/recon/httprobe/alive.txt -T4 -oA $url/recon/scans/scanned.txt
        echo "----------------------------------------------"

        echo "*** Scraping WAYBACK data ***"
        cat $url/recon/httprobe/alive.txt|waybackurls>>$url/recon/wayback/output.txt
        sort -u $url/recon/wayback/output.txt | anew $url/recon/wayback/wayback_output.txt
        rm $url/recon/wayback/output.txt
        echo "----------------------------------------------"

        echo "*** Pulling and compiling all possible params found in wayback data ***"
        cat $url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback/params/wayback_params.txt
        for line in $(cat $url/recon/wayback/params/wayback_params.txt);do echo $line'=';done
        echo "----------------------------------------------"

        echo "*** Pulling and compiling js/php/aspx/jsp/json files from wayback output ***"
        for line in $(cat $url/recon/wayback/wayback_output.txt);do
                ext="${line##*.}"
                if [[ "$ext" == "js" ]]; then
                        echo $line >> $url/recon/wayback/extensions/js1.txt
                        sort -u $url/recon/wayback/extensions/js1.txt >> $url/recon/wayback/extensions/js.txt
                fi
                if [[ "$ext" == "html" ]];then
                        echo $line >> $url/recon/wayback/extensions/jsp1.txt
                        sort -u $url/recon/wayback/extensions/jsp1.txt >> $url/recon/wayback/extensions/jsp.txt
                fi
                if [[ "$ext" == "json" ]];then
                        echo $line >> $url/recon/wayback/extensions/json1.txt
                        sort -u $url/recon/wayback/extensions/json1.txt >> $url/recon/wayback/extensions/json.txt
                fi
                if [[ "$ext" == "php" ]];then
                        echo $line >> $url/recon/wayback/extensions/php1.txt
                        sort -u $url/recon/wayback/extensions/php1.txt >> $url/recon/wayback/extensions/php.txt
                fi
                if [[ "$ext" == "aspx" ]];then
                        echo $line >> $url/recon/wayback/extensions/aspx1.txt
                        sort -u $url/recon/wayback/extensions/aspx1.txt >> $url/recon/wayback/extensions/aspx.txt
                fi
        done

        rm $url/recon/wayback/extensions/js1.txt
        rm $url/recon/wayback/extensions/jsp1.txt
        rm $url/recon/wayback/extensions/json1.txt
        rm $url/recon/wayback/extensions/php1.txt
        rm $url/recon/wayback/extensions/aspx1.txt

        echo "------------------------------------------------"
        echo "*** Running GOWITNESS against all compiled domains ***"
        gowitness file -f $url/recon/httprobe/alive.txt -P $url/recon/gowitness/
        echo "------------------------------------------------"
fi