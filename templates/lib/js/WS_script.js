
var projectName = 'White Snake';
var supportUrl = 'https://t.me/WhiteSnake_Support';

// Dark/Light theme
var head = document.getElementsByTagName('head')[0];
var current_mode = getCookie('theme', 'light');

var backendCheckInterval;
function checkBackend() {
    // Eel host disconnected
    if (typeof eel != 'undefined') {
        if (eel._websocket.readyState != 1) {
            clearInterval(backendCheckInterval);
            try { lock_connections(); } catch { }
            UIkit.modal.alert('Backend disconnected, look console for errors.');
            setTimeout(() => {
                close_window();
            }, 1000);
        }
    } 
}

async function streamToBase64(readableStream) {
    // Step 1: Convert ReadableStream to Blob
    const blob = await new Response(readableStream).blob();

    // Step 2: Convert Blob to base64
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onloadend = function() {
        // Remove the prefix "data:[...];base64," from the Data URL
        const base64data = reader.result.split(',')[1];
            resolve(base64data);
        };
        reader.onerror = function(error) {
            reject(error);
        };
        reader.readAsDataURL(blob);
    });
}

function b64DecodeUnicode(str) {
    try {
        // Going backwards: from bytestream, to percent-encoding, to original string.
        return decodeURIComponent(atob(str).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
    } catch {
        return atob(str);
    }
}

window.addEventListener('load', (e) => {
    // Check backend
    backendCheckInterval = setInterval(checkBackend, 3000);
    // Replace values
    let title = document.querySelector('title');
    title.innerText = projectName + ' | ' + title.innerText;
    document.getElementById('project_name').innerText = projectName;
});

eel.expose(refresh_window);
function refresh_window() { window.location.reload(); }

eel.expose(set_location);
function set_location(path) { window.location.href = path; }

eel.expose(get_location);
function get_location() { return window.location.href; }

eel.expose(close_window);
function close_window() { window.close(); }

eel.expose(notification);
function notification(text, icon, timeout = 2000) {
    return UIkit.notification(
        `<iconify-icon icon=\"${icon}\"></iconify-icon> ${text}`, 
        {pos: 'bottom-right', timeout: timeout}
    );
}

// Write text into clipboard
function copy(self) {
    if (self.target.textContent.length > 0) {
        copy_text(self.target.textContent);
    }
}

function copy_text(text) {
    navigator.clipboard.writeText(text).then(function() {
        console.log('Async: Copying to clipboard was successful!');
        notification('Copied to clipboard', 'material-symbols:content-copy-outline');
    }, function(err) {
        notification('Failed to copy data"', 'material-symbols:content-copy-outline');
        console.error('Async: Could not copy text: ', err);
    });
}
function encodeHTML(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
}
function lightMode() {
    document.getElementById('dark-mode-css').remove();
}
function darkMode() {
    head.insertAdjacentHTML(
        "beforeend", 
        "<link rel=\"stylesheet\" id=\"dark-mode-css\" href=\"lib/css/dark.css\" />"
    );
}
function toggleDarkMode() {
    current_mode = getCookie('theme', 'light');
    if (current_mode == 'light') {
        setCookie('theme', 'dark');
        darkMode();
    } else {
        setCookie('theme', 'light');
        lightMode();
    }
}

if (current_mode == 'dark') { darkMode(); }

// Download file
eel.expose(downloadFile);
function downloadFile(filename, data, decode=true) {
    notification('Downloading ' + filename, 'basil:file-download-outline');
    let binaryString = decode ? window.atob(data) : data;
    let binaryLen = binaryString.length;
    let bytes = new Uint8Array(binaryLen);
    for (let i = 0; i < binaryLen; i++) {
        let ascii = binaryString.charCodeAt(i);
        bytes[i] = ascii;
    }
    let blob = new Blob([bytes], {type: "data:text/plain;charset=utf-8"});
    let link = document.createElement('a');
    link.href = window.URL.createObjectURL(blob);
    link.download = filename;
    link.click();
};

// Cookies control
function setCookie(name, value, days=999) {
    var expires = "";
    if (days) {
        var date = new Date();
        date.setTime(date.getTime() + (days*24*60*60*1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "")  + expires + "; path=/";
}
function getCookie(name, default_value=null) {
    var nameEQ = name + "=";
    var ca = document.cookie.split(';');
    for(var i=0;i < ca.length;i++) {
        var c = ca[i];
        while (c.charAt(0)==' ') c = c.substring(1,c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
    }
    return default_value;
}
function eraseCookie(name) {   
    document.cookie = name +'=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
}