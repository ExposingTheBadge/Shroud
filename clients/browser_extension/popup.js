/*
 * Popup UI: pick a contact, write a message, send via background.
 */

const contactSelect = document.getElementById('contact');
const bodyTextarea = document.getElementById('body');
const sendBtn = document.getElementById('send');
const statusEl = document.getElementById('status');

async function init() {
    const { shroud_contacts } = await chrome.storage.local.get('shroud_contacts');
    const contacts = shroud_contacts || [];
    for (const c of contacts) {
        const opt = document.createElement('option');
        opt.value = c.name;
        opt.textContent = c.name;
        contactSelect.appendChild(opt);
    }
    if (contacts.length === 0) {
        const opt = document.createElement('option');
        opt.textContent = '(no contacts — set in Options)';
        opt.disabled = true;
        contactSelect.appendChild(opt);
    }

    // Preload selected text if context menu fired
    const { shroud_pending_send } = await chrome.storage.session.get('shroud_pending_send');
    if (shroud_pending_send) {
        bodyTextarea.value = shroud_pending_send;
        await chrome.storage.session.remove('shroud_pending_send');
    }
}

sendBtn.addEventListener('click', async () => {
    const contactName = contactSelect.value;
    const body = bodyTextarea.value.trim();
    if (!contactName || !body) {
        statusEl.textContent = 'pick a contact and write a message';
        statusEl.className = 'status err';
        return;
    }
    statusEl.textContent = 'sealing + sending…';
    statusEl.className = 'status';

    chrome.runtime.sendMessage(
        { type: 'shroud_send_to_contact', contactName, body },
        (resp) => {
            if (resp && resp.ok) {
                statusEl.textContent = `sent (id=${resp.message_id})`;
                statusEl.className = 'status ok';
                bodyTextarea.value = '';
            } else {
                statusEl.textContent = `failed: ${resp?.error || 'unknown'}`;
                statusEl.className = 'status err';
            }
        }
    );
});

init();
