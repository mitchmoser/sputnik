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
    "id": "--All IP--",
    "title": "Open in all",
    "contexts": ["selection", "link", "image", "video", "audio"],
    "parentId": "IP"
});

chrome.contextMenus.create({
    "id": "AbuseIPDB",
    "title": "AbuseIPDB",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Alien IP",
    "title": "AlienVault OTX",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "ARIN IP",
    "title": "ARIN",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Bad Packets IP",
    "title": "Bad Packets",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
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
    "id": "HackerTarget Reverse IP",
    "title": "HackerTarget",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "IPinfo IP",
    "title": "IPinfo",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "IP Quality Score",
    "title": "IP Quality Score",
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
    "id": "MX Toolbox ARIN IP",
    "title": "MX Toolbox",
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
    "id": "Spyse IP",
    "title": "Spyse",
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
    "id": "TOR IP",
    "title": "TOR Relay",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "URLhaus IP",
    "title": "URLhaus",
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
    "id": "--All Domain--",
    "title": "Open in all",
    "contexts": ["selection", "link", "image", "video", "audio"],
    "parentId": "Domain"
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
    "id": "host.io Domain",
    "title": "host.io",
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
    "id": "Spyse Domain",
    "title": "Spyse",
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
    "id": "TOR Domain",
    "title": "TOR Relay",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "URLhaus Domain",
    "title": "URLhaus",
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
    "id": "--All Hash--",
    "title": "Open in all",
    "contexts": ["selection"],
    "parentId": "Hash",
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
    "id": "URLhaus Hash",
    "title": "URLhaus",
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
    "id": "--All URL--",
    "title": "Open in all",
    "contexts": ["selection", "link", "image", "video", "audio"],
    "parentId": "URL"
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
    "id": "urlvoid",
    "title": "urlvoid",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "URLhaus URL",
    "title": "URLhaus",
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
var urls = [];

// create empty artifact variable
var artifact = "";

// Open all tabs flag variable
var fallthrough = false;

/*
 * Source:
 * https://stackoverflow.com/questions/13899299/write-text-to-clipboard#18258178
 * Note: Renamed function to match it's use case in Manifest V3
 */
function injectCopyStringToClipboard(str) {
    // Create new element
    var el = document.createElement("textarea");
    // Set value (string to be copied)
    el.value = str;
    // Set non-editable to avoid focus and move outside of view
    el.setAttribute("readonly", "");
    el.style = {position: "absolute", left: "-9999px"};
    document.body.appendChild(el);
    // Select text inside element
    el.select();
    // Copy text to clipboard
    document.execCommand("copy");
    // Remove temporary element
    document.body.removeChild(el);
}

/* 
 * New function using chrome.scripting to inject the copyStringToClipboard into current active tab.
 * This was the only "workaround" to having clipboards work in Manifest V3 since the Servcie Workers
 * no longer have access to the DOM in V3, which breaks all the old functionality.
 */
function copyStringToClipboard(str) {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        var currTab = tabs[0];
        if (currTab) 
        {
            chrome.scripting.executeScript({
                target: {tabId: currTab.id},
                func: injectCopyStringToClipboard,
                args: [str],
            });
        }
    });
}

function sanitizeArtifact(artifact) {
    while(artifact.includes("[.]")) {
        artifact = artifact.replace("[.]", ".");
    }

    if(artifact.includes("hxxp://")) {
        artifact = artifact.replace("hxxp://", "http://");
    }

    if(artifact.includes("hxxps://")) {
        artifact = artifact.replace("hxxps://", "https://");
    }
    return artifact;
}

/*
 * The click event listener: 
 * where we perform the approprate action 
 * given the ID of the menu item that was clicked
 */
chrome.contextMenus.onClicked.addListener((info, tab) => {
    // identify context type and strip leading and trailing spaces
    if (info.selectionText) {
        artifact = String(info.selectionText).trim();
    } else if (info.linkUrl) {
        var link = new URL(info.linkUrl);
        artifact = link.host;
    } else if (info.srcUrl) {
        var src = new URL(info.srcUrl);
        artifact = src.host;
    }

    // unsanitize artifact if it is secured against clicking
    artifact = sanitizeArtifact(artifact);
    fallthrough = false;
    urls = [];

    // copy the selection to clipboard
    copyStringToClipboard(artifact);

    switch (info.menuItemId) {

            /*
             * IPs
             */
            
            case "--All IP--":
                fallthrough = true;

            case "AbuseIPDB":
                urls.push("https://www.abuseipdb.com/check/"+artifact);
                if (!fallthrough) { break; }

            case "Alien IP":
                urls.push("https://otx.alienvault.com/indicator/ip/"+artifact);
                if (!fallthrough) { break; }

            case "ARIN IP":
                urls.push("https://search.arin.net/rdap/?query="+artifact);
                if (!fallthrough) { break; }

            case "Bad Packets IP":
                urls.push("https://mirai.badpackets.net/?source_ip_address="+artifact);
                if (!fallthrough) { break; }

            case "Censys IP":
                urls.push("https://censys.io/ipv4/"+artifact);
                if (!fallthrough) { break; }

            case "FortiGuard IP":
                urls.push("https://fortiguard.com/search?q="+artifact+"&engine=8");
                if (!fallthrough) { break; }

            case "GreyNoise IP":
                urls.push("https://viz.greynoise.io/ip/"+artifact);
                if (!fallthrough) { break; }

            case "HackerTarget Reverse IP":
                urls.push("https://api.hackertarget.com/reverseiplookup/?q="+artifact);
                if (!fallthrough) { break; }


            case "IPinfo IP":
                urls.push("https://ipinfo.io/"+artifact);
                if (!fallthrough) { break; }

            case "IP Quality Score":
                urls.push("https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/"+artifact);
                if (!fallthrough) { break; }

            case "IPVoid IP":
                urls.push("https://www.ipvoid.com/");
                if (!fallthrough) { break; }

            case "MX Toolbox ARIN IP":
                urls.push("https://www.mxtoolbox.com/SuperTool.aspx?action=arin%3a"+artifact);
                if (!fallthrough) { break; }

            case "Pulsedive IP":
                urls.push("https://pulsedive.com/indicator/?ioc="+btoa(artifact)); // btoa() = base64 encode
                if (!fallthrough) { break; }

            case "SecurityTrails IP":
                urls.push("https://securitytrails.com/list/ip/"+artifact);
                if (!fallthrough) { break; }

            case "Shodan IP":
                urls.push("https://www.shodan.io/host/"+artifact);
                if (!fallthrough) { break; }

            case "Spyse IP":
                urls.push("https://spyse.com/target/ip/"+artifact);
                if (!fallthrough) { break; }

            case "Talos IP":
                urls.push("https://talosintelligence.com/reputation_center/lookup?search="+artifact);
                if (!fallthrough) { break; }

            case "ThreatCrowd IP":
                urls.push("https://www.threatcrowd.org/pivot.php?data="+artifact);
                if (!fallthrough) { break; }

            case "ThreatMiner IP":
                urls.push("https://www.threatminer.org/host.php?q="+artifact);
                if (!fallthrough) { break; }

            case "TOR IP":
                urls.push("https://metrics.torproject.org/rs.html#search/"+artifact);
                if (!fallthrough) { break; }

            case "URLhaus IP":
                urls.push("https://urlhaus.abuse.ch/browse.php?search="+artifact);
                if (!fallthrough) { break; }

            case "VT IP":
                urls.push("https://www.virustotal.com/#/ip-address/"+artifact);
                if (!fallthrough) { break; }

            case "X-Force IP":
                urls.push("https://exchange.xforce.ibmcloud.com/ip/"+artifact);
                break;

            /*
             * Domains
             */

            case "--All Domain--":
                fallthrough = true;

            case "Alexa Domain":
                urls.push("https://www.alexa.com/siteinfo/"+artifact);
                if (!fallthrough) { break; }

            case "BlueCoat Domain":
                urls.push("https://sitereview.bluecoat.com/#/lookup-result/"+artifact);
                if (!fallthrough) { break; }

            case "Censys Domain":
                urls.push("https://censys.io/domain?q="+artifact);
                if (!fallthrough) { break; }

            case "FortiGuard Domain":
                urls.push("https://fortiguard.com/search?q="+artifact+"&engine=1");
                if (!fallthrough) { break; }

            case "host.io Domain":
                urls.push("https://host.io/"+artifact);
                if (!fallthrough) { break; }

            case "MX Toolbox Domain":
                urls.push("https://mxtoolbox.com/SuperTool.aspx?action=mx%3a"+artifact+"&run=toolpage");
                if (!fallthrough) { break; }

            case "Pulsedive Domain":
                urls.push("https://pulsedive.com/indicator/?ioc="+btoa(artifact)); // btoa() = base64 encode
                if (!fallthrough) { break; }

            case "SecurityTrails Domain":
                urls.push("https://securitytrails.com/domain/"+artifact+"/dns");
                if (!fallthrough) { break; }

            case "Shodan Domain":
                urls.push("https://www.shodan.io/search?query="+artifact);
                if (!fallthrough) { break; }

            case "Spyse Domain":
                urls.push("https://spyse.com/target/domain/"+artifact);
                if (!fallthrough) { break; }

            case "Talos Domain":
                urls.push("https://talosintelligence.com/reputation_center/lookup?search="+artifact);
                if (!fallthrough) { break; }

            case "ThreatCrowd Domain":
                urls.push("https://www.threatcrowd.org/pivot.php?data="+artifact);
                if (!fallthrough) { break; }

            case "ThreatMiner Domain":
                urls.push("https://www.threatminer.org/domain.php?q="+artifact);
                if (!fallthrough) { break; }

            case "TOR Domain":
                urls.push("https://metrics.torproject.org/rs.html#search/"+artifact);
                if (!fallthrough) { break; }

            case "URLhaus Domain":
                urls.push("https://urlhaus.abuse.ch/browse.php?search="+artifact);
                if (!fallthrough) { break; }

            case "VT Domain":
                urls.push("https://virustotal.com/#/domain/"+artifact);
                if (!fallthrough) { break; }

            case "X-Force Domain":
                urls.push("https://exchange.xforce.ibmcloud.com/url/"+artifact);
                break;

            /*
             * Hashes
             */
        
            case "--All Hash--":
                fallthrough = true;

            case "Alien Hash":
                urls.push("https://otx.alienvault.com/indicator/file/"+artifact);
                if (!fallthrough) { break; }

            case "Hybrid Hash":
                urls.push("https://www.hybrid-analysis.com/search?query="+artifact);
                if (!fallthrough) { break; }

            case "Talos Hash":
                urls.push("https://talosintelligence.com/talos_file_reputation");
                if (!fallthrough) { break; }

            case "ThreatMiner Hash":
                urls.push("https://www.threatminer.org/sample.php?q="+artifact);
                if (!fallthrough) { break; }

            case "URLhaus Hash":
                urls.push("https://urlhaus.abuse.ch/browse.php?search="+artifact);
                if (!fallthrough) { break; }

            case "VT Hash":
                urls.push("https://www.virustotal.com/#/file/"+artifact);
                if (!fallthrough) { break; }

            case "X-Force Hash":
                urls.push("https://exchange.xforce.ibmcloud.com/malware/"+artifact);
                break;

            /*
             * URLs
             */

            case "--All URL--":
                fallthrough = true;

            case "Any.Run":
                urls.push("https://app.any.run/");
                if (!fallthrough) { break; }

            case "BlueCoat URL":
                urls.push("https://sitereview.bluecoat.com/#/lookup-result/");
                if (!fallthrough) { break; }

            case "FortiGuard URL":
                urls.push("https://fortiguard.com/search?q="+artifact+"&engine=7");
                if (!fallthrough) { break; }

            case "HackerTarget":
                urls.push("https://hackertarget.com/extract-links/");
                if (!fallthrough) { break; }

            case "TrendMicro URL":
                urls.push("https://global.sitesafety.trendmicro.com/");
                if (!fallthrough) { break; }

            case "URLhaus URL":
                urls.push("https://urlhaus.abuse.ch/browse.php?search="+artifact);
                if (!fallthrough) { break; }

            case "urlscan":
                urls.push("https://urlscan.io/");
                if (!fallthrough) { break; }

            case "urlvoid":
                urls.push("https://urlvoid.com/scan/"+artifact);
                if (!fallthrough) { break; }
            
            case "VT URL":
                urls.push("https://www.virustotal.com/#/home/url");
                if (!fallthrough) { break; }

            case "X-Force URL":
                urls.push("https://exchange.xforce.ibmcloud.com/url/"+artifact);
                if (!fallthrough) { break; }

            case "zscaler":
                urls.push("https://zulu.zscaler.com/");
                break;
    }

    // Open one or all tabs
    urls.forEach((url) => {
        chrome.tabs.create({url});
    });
});
