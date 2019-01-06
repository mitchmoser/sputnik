<p align="center">
    <img src="https://raw.githubusercontent.com/mitchmoser/sputnik/master/screenshots/sputnik%20logo.png"
        height="150">
</p>

# Sputnik OSINT Extension

[![Chrome Users](https://img.shields.io/chrome-web-store/users/:sputnik/manapjdamopgbpimgojkccikaabhmocd.svg?style=popout&logo=google%20chrome&logoColor=dddddd)](https://chrome.google.com/webstore/detail/sputnik/manapjdamopgbpimgojkccikaabhmocd) [![Chrome Version](https://img.shields.io/chrome-web-store/v/:sputnik/manapjdamopgbpimgojkccikaabhmocd.svg?style=popout&logo=google%20chrome&colorB=green&logoColor=dddddd)](https://chrome.google.com/webstore/detail/sputnik/manapjdamopgbpimgojkccikaabhmocd) [![Chrome Stars](https://img.shields.io/chrome-web-store/stars/:sputnik/manapjdamopgbpimgojkccikaabhmocd.svg?style=popout&logo=google%20chrome&logoColor=dddddd)](https://chrome.google.com/webstore/detail/sputnik/manapjdamopgbpimgojkccikaabhmocd)

[![Firefox Users](https://img.shields.io/amo/users/:addon/sputnik-osint/.svg?style=popout&logo=mozilla%20firefox)](https://addons.mozilla.org/en-US/firefox/addon/sputnik-osint/) [![Firefox Version](https://img.shields.io/amo/v/:addon/sputnik-osint/.svg?style=popout&logo=mozilla%20firefox&colorB=green)](https://addons.mozilla.org/en-US/firefox/addon/sputnik-osint/) [![Firefox Stars](https://img.shields.io/amo/stars/:addon/sputnik-osint/.svg?style=popout&logo=mozilla%20firefox)](https://addons.mozilla.org/en-US/firefox/addon/sputnik-osint/)

[![Codacy Badge](https://img.shields.io/codacy/grade/b42064f2ffca4e8e966e0a1fe8f8c4ea/master.svg?style=popout&logo=codacy&logoColor=dddddd)](https://app.codacy.com/app/mitchmoser/sputnik?utm_source=github.com&utm_medium=referral&utm_content=mitchmoser/sputnik&utm_campaign=Badge_Grade_Dashboard) [![Vulnerabilities Snyk.io](https://img.shields.io/snyk/vulnerabilities/github/mitchmoser/sputnik.svg?style=popout&logo=javascript)](https://snyk.io/test/github/mitchmoser/sputnik?targetFile=package.json) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=popout&logo=github&logoColor=dddddd)](https://github.com/mitchmoser/sputnik/pulls)

Sputnik is an extension to quickly and easily search IPs, Domains, File Hashes, and URLs using free Open Source Intelligence (OSINT) resources.

## Usage
  - **Text**: Select the artifact you wish to search and right click
  - **Links**: Right click on links, audio, images, videos
  - Select an OSINT tool
    - In most cases, you will be redirected straight to results
    - For tools that require user interaction such as captchas:
      - The highlighted artifact will be saved to your clipboard
      - You will be directed to the submission page

## Firefox
[![](screenshots/firefox.png?raw=true)](https://addons.mozilla.org/en-US/firefox/addon/sputnik-osint/)

Available through [Mozilla](https://addons.mozilla.org/en-US/firefox/addon/sputnik-osint/)

![](screenshots/sputnik-firefox.png?raw=true)

## Chrome
[![](screenshots/chrome.png?raw=true)](https://chrome.google.com/webstore/detail/sputnik/manapjdamopgbpimgojkccikaabhmocd)

Available through [Chrome Web Store](https://chrome.google.com/webstore/detail/sputnik/manapjdamopgbpimgojkccikaabhmocd)
![](screenshots/sputnik-chrome.png?raw=true)

## OSINT Resources

The following OSINT resources have been implemented for each artifact type:

### IP
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [AlienVault OTX](https://otx.alienvault.com/)
  - [Bad Packets](https://badpackets.net/)
  - [Censys](https://censys.io/)
  - [FortiGuard](http://fortiguard.com/)
  - [GreyNoise](https://greynoise.io/)
  - [IPVoid](http://www.ipvoid.com/)
  - [Onyphe](https://www.onyphe.io/)
  - [Pulsedive](https://pulsedive.com/)
  - [SecurityTrails](https://securitytrails.com/)
  - [Shodan](https://www.shodan.io/)
  - [Talos](https://talosintelligence.com/)
  - [ThreatCrowd](https://www.threatcrowd.org/)
  - [ThreatMiner](https://www.threatminer.org/)
  - [VirusTotal](https://www.virustotal.com/#/home/upload)
  - [X-Force](https://exchange.xforce.ibmcloud.com/)

### Domain
  - [Alexa](https://www.alexa.com/siteinfo)
  - [BlueCoat](http://sitereview.bluecoat.com/#/)
  - [Censys](https://censys.io/)
  - [FortiGuard](http://fortiguard.com/)
  - [MX Toolbox](https://mxtoolbox.com/)
  - [Onyphe](https://www.onyphe.io/)
  - [Pulsedive](https://pulsedive.com/)
  - [SecurityTrails](https://securitytrails.com/)
  - [Shodan](https://www.shodan.io/)
  - [Talos](https://talosintelligence.com/)
  - [ThreatCrowd](https://www.threatcrowd.org/)
  - [ThreatMiner](https://www.threatminer.org/)
  - [VirusTotal](https://www.virustotal.com/#/home/upload)
  - [X-Force](https://exchange.xforce.ibmcloud.com/)

### File Hash
  - [AlienVault OTX](https://otx.alienvault.com/)
  - [Hybrid Analysis](https://www.hybrid-analysis.com/)
  - [Talos](https://talosintelligence.com/)
  - [ThreatMiner](https://www.threatminer.org/)
  - [VirusTotal](https://www.virustotal.com/#/home/upload)
  - [X-Force](https://exchange.xforce.ibmcloud.com/)

### URL
  - [Any.Run](https://app.any.run/)
  - [BlueCoat](http://sitereview.bluecoat.com/#/)
  - [Extract Links](https://hackertarget.com/extract-links/)
  - [FortiGuard](http://fortiguard.com/)
  - [TrendMicro](https://global.sitesafety.trendmicro.com/)
  - [urlscan](https://urlscan.io/)
  - [VirusTotal](https://www.virustotal.com/#/home/upload)
  - [X-Force](https://exchange.xforce.ibmcloud.com/)
  - [Zscaler](https://zulu.zscaler.com/)
