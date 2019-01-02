// create a context menu
/*
 * IPs
 */
chrome.contextMenus.create({
    "id": "IP",
    "title": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Alien IP",
    "title": "AlienVault OTX",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Bad Packets IP",
    "title": "Bad Packets",
    "parentId": "IP",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "Censys IP",
    "title": "Censys",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "FortiGuard IP",
    "title": "FortiGuard",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "GreyNoise IP",
    "title": "GreyNoise",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "IPVoid IP",
    "title": "IPVoid",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Onyphe IP",
    "title": "Onyphe",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Pulsedive IP",
    "title": "Pulsedive",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "SecurityTrails IP",
    "title": "SecurityTrails",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Shodan IP",
    "title": "Shodan",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Talos IP",
    "title": "Talos",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "ThreatCrowd IP",
    "title": "ThreatCrowd",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "ThreatMiner IP",
    "title": "ThreatMiner",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "VT IP",
    "title": "VirusTotal",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "X-Force IP",
    "title": "X-Force",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

/*
 * Domains
 */
chrome.contextMenus.create({
    "id": "Domain",
    "title": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Alexa Domain",
    "title": "Alexa",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "BlueCoat Domain",
    "title": "BlueCoat",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Censys Domain",
    "title": "Censys",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "FortiGuard Domain",
    "title": "FortiGuard",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "MX Toolbox Domain",
    "title": "MX Toolbox",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Onyphe Domain",
    "title": "Onyphe",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Pulsedive Domain",
    "title": "Pulsedive",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "SecurityTrails Domain",
    "title": "SecurityTrails",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Shodan Domain",
    "title": "Shodan",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Talos Domain",
    "title": "Talos",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "ThreatCrowd Domain",
    "title": "ThreatCrowd",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "ThreatMiner Domain",
    "title": "ThreatMiner",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "VT Domain",
    "title": "VirusTotal",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "X-Force Domain",
    "title": "X-Force",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

/*
 * Hashes
 */
chrome.contextMenus.create({
    "id": "Hash",
    "title": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "Alien Hash",
    "title": "AlienVault OTX",
    "parentId": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "Hybrid Hash",
    "title": "Hybrid Analysis",
    "parentId": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "Talos Hash",
    "title": "Talos",
    "parentId": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "ThreatMiner Hash",
    "title": "ThreatMiner",
    "parentId": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "VT Hash",
    "title": "VirusTotal",
    "parentId": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "X-Force Hash",
    "title": "X-Force",
    "parentId": "Hash",
    "contexts": ["selection"]
});

/*
 * URLs
 */
chrome.contextMenus.create({
    "id": "URL",
    "title": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Any.Run",
    "title": "Any.Run",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "BlueCoat URL",
    "title": "BlueCoat",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "HackerTarget",
    "title": "Extract Links",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "FortiGuard URL",
    "title": "FortiGuard",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "TrendMicro",
    "title": "TrendMicro",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "urlscan",
    "title": "urlscan",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "VT URL",
    "title": "VirusTotal",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "X-Force URL",
    "title": "X-Force",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "zscaler",
    "title": "Zscaler",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

// create empty url variable
var url = ""

/*
 * Source:
 * https://stackoverflow.com/questions/13899299/write-text-to-clipboard#18258178
 */
function copyStringToClipboard(str) {
    // Create new element
    var el = document.createElement('textarea');
    // Set value (string to be copied)
    el.value = str;
    // Set non-editable to avoid focus and move outside of view
    el.setAttribute('readonly', '');
    el.style = {position: 'absolute', left: '-9999px'};
    document.body.appendChild(el);
    // Select text inside element
    el.select();
    // Copy text to clipboard
    document.execCommand('copy');
    // Remove temporary element
    document.body.removeChild(el);
    }

/*
 * The click event listener: 
 * where we perform the approprate action 
 * given the ID of the menu item that was clicked
 */
chrome.contextMenus.onClicked.addListener((info, tab) => {
    // identify context type and strip leading and trailing spaces
    if (info.selectionText) {
        var artifact = String(info.selectionText).trim()
    } else if (info.linkUrl) {
        var artifact = new URL(info.linkUrl)
        artifact = domain.host;
    } else if (info.srcUrl) {
        var artifact = new URL(info.srcUrl)
        artifact = domain.host;
    }
    // copy the selection to clipboard
    copyStringToClipboard(artifact);

    switch (info.menuItemId) {
            /*
             * IPs
             */
            case "Alien IP":
                url = "https://otx.alienvault.com/indicator/ip/"+artifact;
                break;
            case "Bad Packets IP":
                url = "https://mirai.badpackets.net/?ipAddress="+artifact;
                break;
            case "Censys IP":
                url = "https://censys.io/ipv4/"+artifact;
                break;
            case "FortiGuard IP":
                url = "http://fortiguard.com/search?q="+artifact+"&engine=8";
                break;
            case "GreyNoise IP":
                url = "https://viz.greynoise.io/ip/"+artifact;
                break;
            case "IPVoid IP":
                url = "http://www.ipvoid.com/";
                break;
            case "Onyphe IP":
                url = "https://www.onyphe.io/search/?query="+artifact;
                break;
            case "Pulsedive IP":
                url = "https://pulsedive.com/indicator/?ioc="+window.btoa(artifact); // btoa() = base64 encode
                break;
            case "SecurityTrails IP":
                url = "https://securitytrails.com/search/domain/"+artifact;
                break;
            case "Shodan IP":
                url = "https://www.shodan.io/host/"+artifact;
                break;
            case "Talos IP":
                url = "https://talosintelligence.com/reputation_center/lookup?search="+artifact;
                break;
            case "ThreatCrowd IP":
                url = "https://www.threatcrowd.org/pivot.php?data="+artifact;
                break;
            case "ThreatMiner IP":
                url = "https://www.threatminer.org/host.php?q="+artifact;
                break;
            case "VT IP":
                url = "https://www.virustotal.com/#/ip-address/"+artifact;
                break;
            case "X-Force IP":
                url = "https://exchange.xforce.ibmcloud.com/ip/"+artifact;
                break;
            /*
             * Domains
             */
            case "Alexa Domain":
                url = "https://www.alexa.com/siteinfo/"+artifact;
                break;
            case "BlueCoat Domain":
                url = "http://sitereview.bluecoat.com/#/lookup-result/"+artifact;
                break;
            case "Censys Domain":
                url = "https://censys.io/domain?q="+artifact;
                break;
            case "FortiGuard Domain":
                url = "http://fortiguard.com/search?q="+artifact+"&engine=1";
                break;
            case "MX Toolbox Domain":
                url = "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a"+artifact+"&run=toolpage";
                break;
            case "Onyphe Domain":
                url = "https://www.onyphe.io/search/?query="+artifact;
                break;
            case "Pulsedive Domain":
                url = "https://pulsedive.com/indicator/?ioc="+window.btoa(artifact); // btoa() = base64 encode
                break;
            case "SecurityTrails Domain":
                url = "https://securitytrails.com/search/domain/"+artifact;
                break;
            case "Shodan Domain":
                url = "https://www.shodan.io/search?query="+artifact;
                break;
            case "Talos Domain":
                url = "https://talosintelligence.com/reputation_center/lookup?search="+artifact;
                break;
            case "ThreatCrowd Domain":
                url = "https://www.threatcrowd.org/pivot.php?data="+artifact;
                break;
            case "ThreatMiner Domain":
                url = "https://www.threatminer.org/domain.php?q="+artifact;
                break;
            case "VT Domain":
                url = "https://virustotal.com/#/domain/"+artifact;
                break;
            case "X-Force Domain":
                url = "https://exchange.xforce.ibmcloud.com/url/"+artifact
                break;
            /*
             * Hashes
             */
            case "Alien Hash":
                url = "https://otx.alienvault.com/indicator/file/"+artifact;
                break;
            case "Hybrid Hash":
                url = "https://www.hybrid-analysis.com/search?query="+artifact;
                break;
            case "Talos Hash":
                url = "https://talosintelligence.com/talos_file_reputation"
                break;
            case "ThreatMiner Hash":
                url = "https://www.threatminer.org/sample.php?q="+artifact;
                break;
            case "VT Hash":
                url = "https://www.virustotal.com/#/file/"+artifact;
                break;
            case "X-Force Hash":
                url = "https://exchange.xforce.ibmcloud.com/malware/"+artifact;
                break;
            /*
             * URLs
             */
            case "Any.Run":
                url = "https://app.any.run/";
                break;
            case "BlueCoat URL":
                url = "http://sitereview.bluecoat.com/#/lookup-result/";
                break;
            case "FortiGuard URL":
                url = "http://fortiguard.com/search?q="+artifact+"&engine=7";
                break;
            case "HackerTarget":
                url = "https://hackertarget.com/extract-links/";
                break;
            case "TrendMicro URL":
                url = "https://global.sitesafety.trendmicro.com/";
                break;
            case "urlscan":
                url = "https://urlscan.io/";
                break;
            case "VT URL":
                url = "https://www.virustotal.com/#/home/url";
                break;
            case "X-Force URL":
                url = "https://exchange.xforce.ibmcloud.com/url/"+artifact
                break;
            case "zscaler":
                url = "https://zulu.zscaler.com/";
                break;
    }
    chrome.tabs.create({url: url});
});
