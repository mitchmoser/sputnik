// create a context menu
/*
 * IPs
 */
browser.contextMenus.create({
    id: "IP",
    title: "IP",
    contexts: ["selection", "link", "image", "video", "audio"]
});

browser.contextMenus.create({
    id: "--All IP--",
    title: "Open in all",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP"
});

browser.contextMenus.create({
    id: "AbuseIPDB",
    title: "AbuseIPDB",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/abuseipdb_48.png"
    }
});

browser.contextMenus.create({
    id: "Alien IP",
    title: "AlienVault OTX",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/alien_48.png"
    }
});

browser.contextMenus.create({
    id: "ARIN IP",
    title: "ARIN",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/arin_48.png"
    }
});

browser.contextMenus.create({
    id: "Bad Packets IP",
    title: "Bad Packets",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/badpackets_48.png"
    }
});

browser.contextMenus.create({
    id: "Censys IP",
    title: "Censys",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/censys_48.png"
    }
});

browser.contextMenus.create({
    id: "FortiGuard IP",
    title: "FortiGuard",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/fortiguard_48.png"
    }
});

browser.contextMenus.create({
    id: "GreyNoise IP",
    title: "GreyNoise",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/greynoise_48.png"
    }
});

browser.contextMenus.create({
    id: "HackerTarget Reverse IP",
    title: "HackerTarget",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/hackertarget_48.png"
    }
});

browser.contextMenus.create({
    id: "IPinfo IP",
    title: "IPinfo",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/ipinfo_48.png"
    }
});

browser.contextMenus.create({
    id: "IP Quality Score",
    title: "IP Quality Score",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/ipqualityscore_48.png"
    }
});

browser.contextMenus.create({
    id: "IPVoid IP",
    title: "IPVoid",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/ipvoid_48.png"
    }
});

browser.contextMenus.create({
    id: "MX Toolbox ARIN IP",
    title: "MX Toolbox",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/mxtoolbox_48.png"
    }
});

browser.contextMenus.create({
    id: "Pulsedive IP",
    title: "Pulsedive",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/pulse_48.png"
    }
});

browser.contextMenus.create({
    id: "SecurityTrails IP",
    title: "SecurityTrails",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/securitytrails_48.png"
    }
});

browser.contextMenus.create({
    id: "Shodan IP",
    title: "Shodan",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/shodan_48.png"
    }
});

browser.contextMenus.create({
    id: "Spyse IP",
    title: "Spyse",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/spyse_48.png"
    }
});

browser.contextMenus.create({
    id: "Talos IP",
    title: "Talos",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/talos_48.png"
    }
});

browser.contextMenus.create({
    id: "ThreatCrowd IP",
    title: "ThreatCrowd",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/threatcrowd_48.png"
    }
});

browser.contextMenus.create({
    id: "ThreatMiner IP",
    title: "ThreatMiner",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/threatminer_48.png"
    }
});

browser.contextMenus.create({
    id: "TOR IP",
    title: "TOR Relay",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/tor_48.png"
    }
});

browser.contextMenus.create({
    id: "URLhaus IP",
    title: "URLhaus",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/urlhaus_48.png"
    }
});

browser.contextMenus.create({
    id: "VT IP",
    title: "VirusTotal",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/vt_48.png"
    }
});

browser.contextMenus.create({
    id: "X-Force IP",
    title: "X-Force",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "IP",
    icons: {
        "48": "icons/xforce_48.png"
    }
});

/*
 * Domains
 */
browser.contextMenus.create({
    id: "Domain",
    title: "Domain",
    contexts: ["selection", "link", "image", "video", "audio"]
});

browser.contextMenus.create({
    id: "--All Domain--",
    title: "Open in all",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain"
});

browser.contextMenus.create({
    id: "Alexa Domain",
    title: "Alexa",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/alexa_48.png"
    }
});

browser.contextMenus.create({
    id: "BlueCoat Domain",
    title: "BlueCoat",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/bluecoat_48.png"
    }
});

browser.contextMenus.create({
    id: "Censys Domain",
    title: "Censys",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/censys_48.png"
    }
});

browser.contextMenus.create({
    id: "FortiGuard Domain",
    title: "FortiGuard",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/fortiguard_48.png"
    }
});

browser.contextMenus.create({
    id: "host.io Domain",
    title: "host.io",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/hostio_48.png"
    }
});

browser.contextMenus.create({
    id: "MX Toolbox Domain",
    title: "MX Toolbox",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/mxtoolbox_48.png"
    }
});

browser.contextMenus.create({
    id: "Pulsedive Domain",
    title: "Pulsedive",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/pulse_48.png"
    }
});

browser.contextMenus.create({
    id: "SecurityTrails Domain",
    title: "SecurityTrails",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/securitytrails_48.png"
    }
});

browser.contextMenus.create({
    id: "Shodan Domain",
    title: "Shodan",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/shodan_48.png"
    }
});

browser.contextMenus.create({
    id: "Spyse Domain",
    title: "Spyse",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/spyse_48.png"
    }
});

browser.contextMenus.create({
    id: "Talos Domain",
    title: "Talos",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/talos_48.png"
    }
});

browser.contextMenus.create({
    id: "ThreatCrowd Domain",
    title: "ThreatCrowd",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/threatcrowd_48.png"
    }
});

browser.contextMenus.create({
    id: "ThreatMiner Domain",
    title: "ThreatMiner",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/threatminer_48.png"
    }
});

browser.contextMenus.create({
    id: "TOR Domain",
    title: "TOR Relay",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/tor_48.png"
    }
});

browser.contextMenus.create({
    id: "URLhaus Domain",
    title: "URLhaus",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/urlhaus_48.png"
    }
});

browser.contextMenus.create({
    id: "VT Domain",
    title: "VirusTotal",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/vt_48.png"
    }
});

browser.contextMenus.create({
    id: "X-Force Domain",
    title: "X-Force",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "Domain",
    icons: {
        "48": "icons/xforce_48.png"
    }
});

/*
 * Hashes
 */
browser.contextMenus.create({
    id: "Hash",
    title: "Hash",
    contexts: ["selection"]
});

browser.contextMenus.create({
    id: "--All Hash--",
    title: "Open in all",
    contexts: ["selection"],
    parentId: "Hash",
});

browser.contextMenus.create({
    id: "Alien Hash",
    title: "AlienVault OTX",
    contexts: ["selection"],
    parentId: "Hash",
    icons: {
        "48": "icons/alien_48.png"
    }
});

browser.contextMenus.create({
    id: "Hybrid Hash",
    title: "Hybrid Analysis",
    contexts: ["selection"],
    parentId: "Hash",
    icons: {
        "48": "icons/hybrid_48.png"
    }
});

browser.contextMenus.create({
    id: "Talos Hash",
    title: "Talos",
    contexts: ["selection"],
    parentId: "Hash",
    icons: {
        "48": "icons/talos_48.png"
    }
});

browser.contextMenus.create({
    id: "ThreatMiner Hash",
    title: "ThreatMiner",
    contexts: ["selection"],
    parentId: "Hash",
    icons: {
        "48": "icons/threatminer_48.png"
    }
});

browser.contextMenus.create({
    id: "URLhaus Hash",
    title: "URLhaus",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "hash",
    icons: {
        "48": "icons/urlhaus_48.png"
    }
});

browser.contextMenus.create({
    id: "VT Hash",
    title: "VirusTotal",
    contexts: ["selection"],
    parentId: "Hash",
    icons: {
        "48": "icons/vt_48.png"
    }
});

browser.contextMenus.create({
    id: "X-Force Hash",
    title: "X-Force",
    contexts: ["selection"],
    parentId: "Hash",
    icons: {
        "48": "icons/xforce_48.png"
    }
});

/*
 * URLs
 */
browser.contextMenus.create({
    id: "URL",
    title: "URL",
    contexts: ["selection", "link", "image", "video", "audio"]
});

browser.contextMenus.create({
    id: "--All URL--",
    title: "Open in all",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "URL"
});

browser.contextMenus.create({
    id: "Any.Run",
    title: "Any.Run",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "URL",
    icons: {
        "48": "icons/anyrun_48.png"
    }
});

browser.contextMenus.create({
    id: "BlueCoat URL",
    title: "BlueCoat",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "URL",
    icons: {
        "48": "icons/bluecoat_48.png"
    }
});

browser.contextMenus.create({
    id: "HackerTarget",
    title: "Extract Links",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "URL",
    icons: {
        "48": "icons/hackertarget_48.png"
    }
});

browser.contextMenus.create({
    id: "FortiGuard URL",
    title: "FortiGuard",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "URL",
    icons: {
        "48": "icons/fortiguard_48.png"
    }
});

browser.contextMenus.create({
    id: "TrendMicro URL",
    title: "TrendMicro",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "URL",
    icons: {
        "48": "icons/trendmicro_48.png"
    }
});

browser.contextMenus.create({
    id: "URLhaus URL",
    title: "URLhaus",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "URL",
    icons: {
        "48": "icons/urlhaus_48.png"
    }
});

browser.contextMenus.create({
    id: "urlscan",
    title: "urlscan",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "URL",
    icons: {
        "48": "icons/urlscan_48.png"
    }
});

browser.contextMenus.create({
    id: "VT URL",
    title: "VirusTotal",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "URL",
    icons: {
        "48": "icons/vt_48.png"
    }
});

browser.contextMenus.create({
    id: "X-Force URL",
    title: "X-Force",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "URL",
    icons: {
        "48": "icons/xforce_48.png"
    }
});

browser.contextMenus.create({
    id: "zscaler",
    title: "Zscaler",
    contexts: ["selection", "link", "image", "video", "audio"],
    parentId: "URL",
    icons: {
        "48": "icons/zscaler_48.png"
    }
});

// create empty url variable
var urls = [];

// create empty artifact variable
var artifact = "";

// Open all tabs flag variable
var fallthrough = false

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

browser.contextMenus.onClicked.addListener((info, tab) => {
    // strip leading and trailing spaces
    if (info.selectionText) {
        artifact = String(info.selectionText).trim();
    } else if (info.linkUrl) {
        var link = new URL(info.linkUrl);
        artifact = link.host;
    } else if (info.srcUrl) {
        var src = new URL(info.srcUrl);
        artifact = src.host;
    }
    // will copy the selection to clipboard after switch statement

    // unsanitize artifact if it is secured against clicking
    artifact = sanitizeArtifact(artifact);
    fallthrough = false;
    urls = [];
    

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
                urls.push("https://pulsedive.com/indicator/?ioc="+window.btoa(artifact)); // btoa() = base64 encode
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
                urls.push("https://pulsedive.com/indicator/?ioc="+window.btoa(artifact)); // btoa() = base64 encode
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
        browser.tabs.create({url});
    })
    
    // copy the selection to clipboard
    navigator.clipboard.writeText(artifact);
});
