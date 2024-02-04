
// Request HWID
async function getHwid() {
    let hwid = (await eel.HardwareID()());
    document.getElementById('identifier').value = hwid;
}

// Activation request
async function activate() {
    let hwid = document.getElementById('identifier').value;
    let license = document.getElementById('license_key').value;
    
    // Check data
    if (!(hwid.length > 20 && license.length > 20)) {
        return UIkit.notification(
            `<span uk-icon="close"></span> Failed to activate, empty data.`, 
            {pos: 'bottom-right', timeout: 3000}
        );
    }
    // Verify license data
    try {
        let result = (await eel.Verify(hwid, license)());
        let icon = result[0] ? 'check' : 'close'
        UIkit.notification(
            `<span uk-icon="${icon}"></span> ${result[1]}`, 
            {pos: 'bottom-right', timeout: 5000}
        );
        if (result[0]) {
            // Write license data
            (await eel.WriteLicense(license)());
            // Close window on success
            setTimeout(() => {
                window.close();
            }, 5000);
        }
        return;
    // Handle error
    } catch (e) {
        console.error(e);
        return UIkit.notification(
            `<span uk-icon="ban"></span> ${e.errorText}`, 
            {pos: 'bottom-right', timeout: 5000}
        );
    }
}

// Fetch HWID
window.addEventListener('load', (e) => {
    getHwid();
});