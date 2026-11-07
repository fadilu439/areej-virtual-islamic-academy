document.addEventListener("DOMContentLoaded", function () {
    const sidebar = document.getElementById("sidebar");
    const toggle = document.getElementById("menuToggle");
    const scrim = document.getElementById("scrim");

    function closeMenu() {
        if (sidebar) sidebar.classList.remove("open");
        if (scrim) scrim.classList.remove("visible");
    }

    if (toggle && sidebar) {
        toggle.addEventListener("click", function () {
            sidebar.classList.toggle("open");
            if (scrim) scrim.classList.toggle("visible");
        });
    }

    if (scrim) scrim.addEventListener("click", closeMenu);

    document.querySelectorAll(".sidebar nav a").forEach(function (link) {
        link.addEventListener("click", function () {
            if (window.innerWidth < 900) closeMenu();
        });
    });

    const passwordInput = document.getElementById("password");
    const togglePassword = document.getElementById("togglePassword");

    if (passwordInput && togglePassword) {
        togglePassword.addEventListener("click", function () {
            const isHidden = passwordInput.type === "password";
            passwordInput.type = isHidden ? "text" : "password";
            togglePassword.textContent = isHidden ? "Hide" : "Show";
        });
    }

    const showStudentForm = document.getElementById("showStudentForm");
    const studentForm = document.getElementById("studentForm");
    if (showStudentForm && studentForm) {
        showStudentForm.addEventListener("click", function () {
            const willOpen = studentForm.hidden;
            studentForm.hidden = !willOpen;
            showStudentForm.setAttribute("aria-expanded", String(willOpen));
            showStudentForm.textContent = willOpen ? "Close" : "+ Add Student";
            if (willOpen) document.getElementById("student_name").focus();
        });
    }

    const showStaffForm = document.getElementById("showStaffForm");
    const staffForm = document.getElementById("staffForm");
    if (showStaffForm && staffForm) {
        showStaffForm.addEventListener("click", function () {
            const willOpen = staffForm.hidden;
            staffForm.hidden = !willOpen;
            showStaffForm.setAttribute("aria-expanded", String(willOpen));
            showStaffForm.textContent = willOpen ? "Close" : "+ Add Staff";
            if (willOpen) document.getElementById("staff_name").focus();
        });
    }

    document.querySelectorAll('.message-form input[type="file"]').forEach(function (input) {
        const wrapper = input.closest('.message-row');
        if (!wrapper || !navigator.mediaDevices || typeof MediaRecorder === 'undefined') return;
        const recordButton = document.createElement('button');
        recordButton.type = 'button'; recordButton.className = 'btn'; recordButton.textContent = 'Record voice note';
        let recorder, chunks = [];
        recordButton.addEventListener('click', async function () {
            if (recorder && recorder.state === 'recording') { recorder.stop(); recordButton.textContent = 'Record voice note'; return; }
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                recorder = new MediaRecorder(stream); chunks = [];
                recorder.ondataavailable = event => { if (event.data.size) chunks.push(event.data); };
                recorder.onstop = function () { stream.getTracks().forEach(track => track.stop()); const blob = new Blob(chunks, {type: recorder.mimeType || 'audio/webm'}); const transfer = new DataTransfer(); transfer.items.add(new File([blob], 'voice-note.webm', {type: blob.type})); input.files = transfer.files; };
                recorder.start(); recordButton.textContent = 'Stop recording';
            } catch (error) { recordButton.textContent = 'Microphone unavailable'; }
        });
        wrapper.appendChild(recordButton);
    });

    const showParentForm = document.getElementById("showParentForm");
    const parentForm = document.getElementById("parentForm");
    if (showParentForm && parentForm) {
        showParentForm.addEventListener("click", function () {
            const willOpen = parentForm.hidden;
            parentForm.hidden = !willOpen;
            showParentForm.setAttribute("aria-expanded", String(willOpen));
            showParentForm.textContent = willOpen ? "Close" : "+ Add Parent";
            if (willOpen) document.getElementById("parent_name").focus();
        });
    }
});
