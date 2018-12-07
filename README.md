![](icons/logo_48.png?raw=true)
# Sputnik OSINT Firefox Extension

Sputnik is an extension to quickly and easily search IPs, Domains, File Hashes, and URLs using free Open Source Intelligence (OSINT) resources.

## Usage
- Highlight the artifact you wish to search
- Select the OSINT tool you want to use
  - In most cases, you will be redirected straight to results
  - For tools that require user interaction such as captchas:
    - The artifact you highlighted will be saved to your clipboard
    - You will be directed to the submission page

## Quick & Dirty Install

After some initial testing & feedback, this will be published as a signed extension through Mozilla.
Until then, it is possible to try this extension out by:
- Downloading this repository
- Navigating to [about:debugging](about:debugging) in Firefox
- Select `Load Temporary Add-on...`
- Choose the `manifest.json` file

![](icons/add-on.png?raw=true)
![](icons/demo.png?raw=true)

# OSINT Resources

The following OSINT resources have been implemented for each artifact type:

## IP
- [AlienVault OTX](https://otx.alienvault.com/)
- [Censys](https://censys.io/)
- [GreyNoise](https://greynoise.io/)
- [IPVoid](http://www.ipvoid.com/)
- [Shodan](https://www.shodan.io/)
- [Cisco Talos](https://talosintelligence.com/)
- [VirusTotal](https://www.virustotal.com/#/home/upload)
- [IBM X-Force](https://exchange.xforce.ibmcloud.com/)

## Domain
- [Alexa](https://www.alexa.com/siteinfo)
- [Censys](https://censys.io/)
- [Shodan](https://www.shodan.io/)
- [Cisco Talos](https://talosintelligence.com/)
- [VirusTotal](https://www.virustotal.com/#/home/upload)
- [IBM X-Force](https://exchange.xforce.ibmcloud.com/)

## File Hash
- [AlienVault OTX](https://otx.alienvault.com/)
- [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [Cisco Talos](https://talosintelligence.com/)
- [VirusTotal](https://www.virustotal.com/#/home/upload)
- [IBM X-Force](https://exchange.xforce.ibmcloud.com/)

## URL
- [Any.Run﻿](https://app.any.run/)
- [Symantec BlueCoat](http://sitereview.bluecoat.com/#/)
- [urlscan](https://urlscan.io/)
- [VirusTotal](https://www.virustotal.com/#/home/upload)
- [Zscaler](https://zulu.zscaler.com/)
