// --------------------
// DECRYPT MODAL
// --------------------

function openDecryptModal(pid) {
    document.getElementById('decrypt-modal').classList.remove('hidden');
    document.getElementById('decrypt-pid').value = pid;

    // reset state
    document.getElementById('decrypt-form').reset();
    document.getElementById('decrypt-result').classList.add('hidden');
    document.getElementById('decrypted-password').value = '';
    document.getElementById('decrypt-form').style.display = 'block';
}

function closeDecryptModal() {
    const modal = document.getElementById('decrypt-modal');
    const field = document.getElementById('decrypted-password');

    // clear sensitive data
    field.value = '';
    field.type = 'password';

    document.getElementById('decrypt-result').classList.add('hidden');
    document.getElementById('decrypt-form').style.display = 'block';

    modal.classList.add('hidden');
}

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('decrypt-form');

    if (form) {
        form.addEventListener('submit', async function(e) {
            e.preventDefault();

            const pid = document.getElementById('decrypt-pid').value;
            const masterpass = document.getElementById('masterpass').value;

            const res = await fetch('/decrypt_password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ pid, masterpass })
            });

            let data;
            try {
                data = await res.json();
            } catch {
                alert('Server error');
                return;
            }

            if (!data.success) {
                alert(data.error);
                return;
            }

            const field = document.getElementById('decrypted-password');
            field.value = data.password;
            field.type = 'password';

            document.getElementById('decrypt-result').classList.remove('hidden');

            // optional: hide form after success
            document.getElementById('decrypt-form').style.display = 'none';
        });
    }
});

// toggle visibility
function togglePassword() {
    const field = document.getElementById('decrypted-password');
    field.type = field.type === 'password' ? 'text' : 'password';
}

// copy to clipboard
function copyPassword() {
    const value = document.getElementById('decrypted-password').value;

    navigator.clipboard.writeText(value)
        .catch(() => alert('Copy failed'));
}


// --------------------
// ADD MODAL
// --------------------

function openAddModal() {
    document.getElementById('add-modal').classList.remove('hidden');
}

function closeAddModal() {
    const field = document.getElementById('add-password');
    field.value = '';
    document.getElementById('add-modal').classList.add('hidden');
}


// --------------------
// UPDATE MODAL
// --------------------

function openUpdateModal(pid) {
    document.getElementById('update-modal').classList.remove('hidden');
    document.getElementById('update-pid').value = pid;
}

function closeUpdateModal() {
    document.getElementById('update-modal').classList.add('hidden');
}


// --------------------
// DELETE MODAL
// --------------------

function openDeleteModal(pid) {
    document.getElementById('delete-modal').classList.remove('hidden');
    document.getElementById('delete-pid').value = pid;
}

function closeDeleteModal() {
    document.getElementById('delete-modal').classList.add('hidden');
}