// new-script.js (v13.3 - Fix Carga Inicial de Skeleton)

const body = document.body;
const moduleContentContainer = document.getElementById('module-content');
const pageTitleMobile = document.getElementById('page-title-mobile');
const toastContainer = document.getElementById('toast-container'); // Contenedor privado
const subidErrorModalEl = document.getElementById('subidErrorModal');
const levelUpModalEl = document.getElementById('levelUpModal');
let subidErrorModal;
let levelUpModal;

// --- Helper Functions ---
function showToast(message, type = 'info', duration = 5000) {
    if (!toastContainer) { console.warn("Toast container not found!"); return; }
    const toastId = 'toast-' + Date.now();
    const textClass = (type === 'warning' || type === 'light' || type === 'info') ? 'text-dark' : 'text-white';
    const closeClass = (type === 'warning' || type === 'light' || type === 'info') ? '' : 'btn-close-white';
    const toastHTML = `<div id="${toastId}" class="toast align-items-center bg-${type} ${textClass} border-0" role="alert" aria-live="assertive" aria-atomic="true" data-bs-delay="${duration}"><div class="d-flex"><div class="toast-body">${escapeHtmlForDisplay(message)}</div><button type="button" class="btn-close ${closeClass} me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button></div></div>`;
    toastContainer.insertAdjacentHTML('beforeend', toastHTML);
    const toastElement = document.getElementById(toastId);
    if (!toastElement) return;
    const toast = new bootstrap.Toast(toastElement);
    toast.show();
    toastElement.addEventListener('hidden.bs.toast', () => toastElement.remove());
}

function updateNavActiveState(targetModuleOrUrl) {
    let currentModule = 'home';
     if (targetModuleOrUrl.includes('admin.php')) {
        const urlParams = new URLSearchParams(new URL(targetModuleOrUrl, window.location.origin).search);
        currentModule = `admin-${urlParams.get('section') || 'dashboard'}`;
     } else if (targetModuleOrUrl.includes('index.php')) {
         const urlParams = new URLSearchParams(new URL(targetModuleOrUrl, window.location.origin).search);
         currentModule = urlParams.get('module') || 'home';
     } else {
         currentModule = targetModuleOrUrl;
     }
    document.querySelectorAll('.app-nav-list li.active, .app-tab-bar a.active').forEach(el => { el.classList.remove('active'); });
    const sidebarLink = document.querySelector(`.app-nav-list a[href*="section=${currentModule.replace('admin-','')}"], .app-nav-list a[href*="module=${currentModule}"]`);
    if (sidebarLink && sidebarLink.closest('li')) { sidebarLink.closest('li').classList.add('active'); }
    const tabBarLink = document.querySelector(`.app-tab-bar a[href*="section=${currentModule.replace('admin-','')}"], .app-tab-bar a[href*="module=${currentModule}"]`);
     if (tabBarLink) {
         if (currentModule.startsWith('admin') && tabBarLink.href.includes('admin.php')) { tabBarLink.classList.add('active'); }
         else if (!currentModule.startsWith('admin') && tabBarLink.href.includes(`module=${currentModule}`)){ tabBarLink.classList.add('active'); }
     }
     if (pageTitleMobile && !currentModule.startsWith('admin')) {
        let title = 'Inicio';
        if (currentModule === 'opensurvey') title = 'JUMPER Opensurvey';
        if (currentModule === 'opinionexchange') title = 'JUMPER OpinionExchange';
        if (currentModule === 'meinungsplatz') title = 'JUMPER Meinungsplatz';
        if (currentModule === 'ranking') title = 'Ranking de SubIDs';
        pageTitleMobile.textContent = title;
     } else if (pageTitleMobile && currentModule.startsWith('admin')) {
         const adminTitleElement = document.querySelector('.content-body h2, .content-body h4');
         pageTitleMobile.textContent = adminTitleElement ? adminTitleElement.textContent.split('(')[0].trim() : 'Admin';
     }
}

function escapeHtmlForDisplay(unsafe) { if (typeof unsafe !== 'string') return ''; return unsafe.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;"); }
function escapeHtml(unsafe) { if (typeof unsafe !== 'string') return ''; return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;"); }
function escapeJsString(unsafe) { if (typeof unsafe !== 'string') return ''; return unsafe.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"'); }
function disposeTooltips() { document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => { const tooltipInstance = bootstrap.Tooltip.getInstance(el); if (tooltipInstance) { tooltipInstance.dispose(); } }); }

async function loadModuleContent(moduleName, pushState = true) {
    if (!moduleContentContainer || !moduleName) return;

    // *** Lógica de Skeleton Loading ***
    let skeletonTemplateId = `skeleton-${moduleName}`;
    const skeletonTemplate = document.getElementById(skeletonTemplateId);

    if (moduleContentContainer.children.length > 0 && !moduleContentContainer.querySelector('.spinner-border')) {
        moduleContentContainer.style.animation = 'pageSlideOut 0.3s ease-out forwards';
    } else {
        // Si es la carga inicial (solo spinner), lo desvanece
        moduleContentContainer.style.animation = 'fadeOut 0.3s ease-out forwards';
    }

    body.classList.add('app-loading');
    disposeTooltips();
    try {
        // Esperar a que la animación de salida termine
        setTimeout(async () => {
            if (skeletonTemplate) {
                // Si encontramos un skeleton, lo mostramos
                moduleContentContainer.innerHTML = skeletonTemplate.innerHTML;
            } else {
                 // Fallback al spinner si no hay skeleton (ej. para un módulo sin skeleton)
                 moduleContentContainer.innerHTML = `<div class="d-flex justify-content-center align-items-center h-100"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Cargando...</span></div></div>`;
            }
            // Activar la animación de entrada
            moduleContentContainer.style.animation = 'pageSlideIn 0.5s cubic-bezier(0.25, 0.46, 0.45, 0.94) forwards';

            // AHORA, hacer la llamada a la API
            const fetchUrl = `index.php?module=${moduleName}&fetch=fragment`;
            const response = await fetch(fetchUrl);
            if (!response.ok) {
                if (response.status === 401) { window.location.href = 'login.php?error=Sesión+expirada.'; return; }
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const html = await response.text();
            
            // Reemplazar el skeleton/spinner con el contenido real
            // (Le damos un pequeño delay para que el skeleton se aprecie)
            setTimeout(() => {
                const currentUrlParams = new URLSearchParams(window.location.search);
                const currentModule = currentUrlParams.get('module') || 'home';
                
                if (currentModule === moduleName) {
                    moduleContentContainer.innerHTML = html;
                    // Inicializar scripts DESPUÉS de que el contenido real esté en su sitio
                    initializeModuleScripts(moduleName);
                }
            }, 150); // 150ms de delay

            body.classList.remove('app-loading');
            
            const targetUrl = `index.php?module=${moduleName}`;
            if (pushState) {
                const currentUrl = window.location.href.split('#')[0];
                const nextUrl = new URL(targetUrl, window.location.origin).href;
                if (currentUrl !== nextUrl) { history.pushState({ module: moduleName }, '', targetUrl); }
            }
            updateNavActiveState(moduleName);
            
        }, 300); // 300ms = duración de pageSlideOut
    } catch (error) {
        console.error('Error loading module:', error);
        moduleContentContainer.innerHTML = `<div class="alert alert-danger">Error al cargar el módulo '${escapeHtmlForDisplay(moduleName)}'. Intenta recargar.</div>`;
        body.classList.remove('app-loading');
        showToast(`Error al cargar ${escapeHtmlForDisplay(moduleName)}.`, 'danger');
        history.replaceState({ module: 'home' }, '', 'index.php?module=home');
        updateNavActiveState('home');
    }
}

function initializeModuleScripts(moduleName) {
    const tooltipTriggerList = [].slice.call(moduleContentContainer.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
      const existingTooltip = bootstrap.Tooltip.getInstance(tooltipTriggerEl);
      if (existingTooltip) existingTooltip.dispose();
      return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    if (moduleName === 'home') {
        getDynamicGreeting();
        fetchHomeStats();
    }
    if (moduleName === 'opensurvey') setupAsyncForm('#opensurvey-form', 'api_generate_opensurvey.php', '#opensurvey-result');
    if (moduleName === 'opinionexchange') setupAsyncForm('#opinionexchange-form', 'api_generate_opinionex.php', '#opinionexchange-result');
    if (moduleName === 'meinungsplatz') initializeMeinungsplatzListeners();
    if (moduleName === 'ranking') fetchRankingData();
}

// --- Navegación SPA ---
document.body.addEventListener('click', (e) => {
    const link = e.target.closest('a');
    if (!link) return;
    if (link.classList.contains('nav-link') && link.closest('.app-sidebar, .app-tab-bar, .modules-container') && link.pathname === window.location.pathname && link.search.includes('module=')) {
        e.preventDefault();
        try {
            const urlParams = new URLSearchParams(link.search);
            const targetModule = urlParams.get('module') || 'home';
            const currentUrlParams = new URLSearchParams(window.location.search);
            const currentModule = currentUrlParams.get('module') || 'home';
            if (targetModule !== currentModule) { loadModuleContent(targetModule); }
        } catch (error) { console.error("Error processing nav link:", error); window.location.href = link.href; }
    }
    else if (link.pathname.includes('admin.php') || link.pathname.includes('logout.php') || link.target === '_blank' || link.hash) { return; }
});
window.addEventListener('popstate', (e) => {
    const state = e.state;
    const targetModule = (state && state.module) ? state.module : 'home';
    loadModuleContent(targetModule, false);
});

// --- Carga Inicial del Módulo ---
const initialUrlParams = new URLSearchParams(window.location.search);
const initialModule = initialUrlParams.get('module') || 'home';
// *** CORRECCIÓN: Volver a llamar a loadModuleContent en la carga inicial ***
requestAnimationFrame(() => { loadModuleContent(initialModule, false); });
// Las siguientes líneas se ejecutarán DENTRO de loadModuleContent ahora.

// --- Formularios Asíncronos (Opensurvey & OpinionExchange) ---
function setupAsyncForm(formSelector, apiUrl, resultSelector) {
    moduleContentContainer.addEventListener('submit', async (e) => {
        if (!e.target.matches(formSelector)) return;
        e.preventDefault();
        const form = e.target;
        const resultContainer = moduleContentContainer.querySelector(resultSelector);
        if (!resultContainer) return;
        resultContainer.innerHTML = '';
        const submitButton = form.querySelector('button[type="submit"]');
        const btnText = submitButton ? submitButton.querySelector('.btn-text') : null;
        const spinner = submitButton ? submitButton.querySelector('.spinner-border') : null;
        if (submitButton) submitButton.disabled = true;
        if (spinner) spinner.classList.remove('d-none');
        if (btnText) btnText.classList.add('loading');
        const formData = new FormData(form);
        try {
            const response = await fetch(apiUrl, { method: 'POST', body: formData });
             const responseText = await response.text();
             let data;
             try { data = JSON.parse(responseText); }
             catch (jsonError) { console.error(`[${formSelector}] JSON Parse Error:`, jsonError, "Response Text:", responseText); throw new Error('Respuesta del servidor inválida.'); }
            
            if (response.status === 401) {
                window.location.href = 'login.php?error=Sesión+expirada+o+inválida.';
                return;
            }

            if (response.ok && data && data.success === true && typeof data.jumper === 'string' && data.jumper.length > 0) {
                const link = data.jumper; 
                const linkForJs = escapeJsString(link);

                resultContainer.innerHTML = `
                    <div class="jumper-success-card">
                        <div class="jsc-icon-wrapper">
                            <i class="bi bi-rocket-launch-fill"></i>
                        </div>
                        <h4 class="jsc-title">¡JUMPER Generado!</h4>
                        <div class="jsc-link-box">
                            <a href="${link}" target="_blank">${link}</a>
                        </div>
                        <div class="jsc-actions">
                            <button class="btn btn-success btn-lg btn-copy-jumper" onclick="copyJumper('${linkForJs}', this)">
                                <i class="bi bi-clipboard-check-fill me-2"></i>Copiar Enlace
                            </button>
                            <a href="${link}" target="_blank" class="btn btn-outline-secondary">
                                <i class="bi bi-box-arrow-up-right me-1"></i>Probar
                            </a>
                        </div>
                    </div>`;
                
                let jumperName = apiUrl.includes('opensurvey') ? 'Opensurvey' : (apiUrl.includes('opinionex') ? 'OpinionEx' : 'Jumper');
                saveToRecentHistory(jumperName, link);
                checkJumperGamification();
                
            } else {
                resultContainer.innerHTML = `<div class="alert alert-warning mt-4">${escapeHtmlForDisplay(data ? data.message : 'Error: Respuesta inválida.')}</div>`;
                showToast(data ? data.message : 'Error al generar.', 'warning');
            }
        } catch (error) {
            console.error(`Error submitting ${formSelector}:`, error);
            resultContainer.innerHTML = `<div class="alert alert-danger mt-4">Error de conexión o respuesta inesperada.</div>`;
            showToast(error.message || 'Error de conexión.', 'danger');
        } finally {
            if (submitButton) submitButton.disabled = false;
            if (spinner) spinner.classList.add('d-none');
            if (btnText) btnText.classList.remove('loading');
        }
    });
}

// --- Efecto Tilt (usando delegación) ---
 if (moduleContentContainer) {
    moduleContentContainer.addEventListener('mousemove', (e) => {
        const card = e.target.closest('.module-card'); if (!card) return;
        const rect = card.getBoundingClientRect(); const x = e.clientX - rect.left; const y = e.clientY - rect.top;
        const { width, height } = rect; const rotateX = (y / height - 0.5) * -20; const rotateY = (x / width - 0.5) * 20;
        card.style.setProperty('--rotateX', `${rotateX}deg`); card.style.setProperty('--rotateY', `${rotateY}deg`);
    });
     moduleContentContainer.addEventListener('mouseleave', (e) => {
         moduleContentContainer.querySelectorAll('.module-card').forEach(card => {
             card.style.setProperty('--rotateX', '0deg'); card.style.setProperty('--rotateY', '0deg');
         });
     }, true);
}

// --- Copiar Jumper (Global - CON TOAST) ---
window.copyJumper = function(text, buttonElement) {
    if (!navigator.clipboard) { showToast("Navegador no soporta copia.", 'warning'); return; }
    navigator.clipboard.writeText(text).then(() => {
        const originalHtml = buttonElement.innerHTML; const originalClasses = buttonElement.className;
         if (buttonElement.classList.contains('btn-copy-lg') || buttonElement.classList.contains('btn-copy-jumper') || buttonElement.classList.contains('btn-copy-history')) {
             buttonElement.innerHTML = '<i class="bi bi-check-all"></i>';
         } else {
             buttonElement.innerHTML = '<i class="bi bi-check-lg me-1"></i>¡Copiado!';
         }
        buttonElement.classList.remove('btn-info', 'btn-success'); buttonElement.classList.add('btn-secondary'); buttonElement.disabled = true;
        showToast('¡Enlace copiado!', 'success', 2000);
        setTimeout(() => { if (document.body.contains(buttonElement)) { buttonElement.innerHTML = originalHtml; buttonElement.className = originalClasses; buttonElement.disabled = false; } }, 2000);
    }).catch(err => {
        console.error('Error al copiar:', err);
         const originalHtml = buttonElement.innerHTML; buttonElement.innerHTML = '<i class="bi bi-x-octagon-fill me-1"></i>Error';
         buttonElement.classList.remove('btn-info', 'btn-success'); buttonElement.classList.add('btn-danger');
          showToast('Error al copiar.', 'danger');
         setTimeout(() => { if (document.body.contains(buttonElement)) { buttonElement.innerHTML = originalHtml; buttonElement.className = originalClasses; buttonElement.disabled = false; } }, 2500);
    });
}

// --- Bloc de Notas ---
const notesPad = document.getElementById('personal-notes-pad');
const notesStatus = document.getElementById('notes-save-status');
let saveTimeout;
document.addEventListener('keyup', (e) => {
    if(e.target && e.target.id === 'personal-notes-pad' && notesStatus) {
        notesStatus.textContent = 'Escribiendo...';
        clearTimeout(saveTimeout);
        saveTimeout = setTimeout(() => {
            localStorage.setItem('personalNotes', e.target.value);
            notesStatus.textContent = '¡Guardado!';
            setTimeout(() => { if(notesStatus) notesStatus.textContent = ''; }, 2000);
        }, 500);
    }
});
const offcanvasElement = document.getElementById('sessionPanelMobile');
if(offcanvasElement && notesPad){
    offcanvasElement.addEventListener('show.bs.offcanvas', function () {
        notesPad.value = localStorage.getItem('personalNotes') || '';
        buildRecentHistory();
    });
}

// --- Modal Novedades ---
const whatsNewModal = document.getElementById('whatsNewModal');
if (whatsNewModal) {
    const appVersion = 'v3.0_AllUXFeatures';
    const hasSeenModal = localStorage.getItem('seenAppVersion');
    if (hasSeenModal !== appVersion) {
        const modal = new bootstrap.Modal(whatsNewModal);
        modal.show();
        localStorage.setItem('seenAppVersion', appVersion);
    }
}

// --- Inactivdad Sesión ---
let inactivityTimer; let countdownTimer; let countdownValue = 60;
const inactivityLimit = 5 * 60 * 1000; // 5 minutos
const modalElement = document.getElementById('inactivityModal');
const countdownElement = document.getElementById('inactivityCountdown');
const stayLoggedInBtn = document.getElementById('stayLoggedInBtn');
const logoutBtn = document.getElementById('logoutBtn');
let inactivityModal;
if (modalElement) { inactivityModal = new bootstrap.Modal(modalElement, { backdrop: 'static', keyboard: false }); }
function resetInactivityTimer() { clearTimeout(inactivityTimer); clearTimeout(countdownTimer); if (inactivityModal && modalElement.classList.contains('show')) { inactivityModal.hide(); } inactivityTimer = setTimeout(showInactivityModal, inactivityLimit); }
function showInactivityModal() { if (!inactivityModal) return; countdownValue = 60; countdownElement.textContent = countdownValue; inactivityModal.show(); startCountdown(); }
function startCountdown() { countdownTimer = setTimeout(() => { countdownValue--; countdownElement.textContent = countdownValue; if (countdownValue <= 0) { logoutUser(); } else { startCountdown(); } }, 1000); }
function logoutUser() { window.location.href = 'logout.php'; }
function stayLoggedIn() { resetInactivityTimer(); }
window.onload = resetInactivityTimer; ['mousemove', 'keypress', 'click', 'scroll', 'touchstart'].forEach(evt => document.addEventListener(evt, resetInactivityTimer, false));
if (stayLoggedInBtn) stayLoggedInBtn.addEventListener('click', stayLoggedIn);
if (logoutBtn) logoutBtn.addEventListener('click', logoutUser);


// --- Lógica del Dashboard de Inicio (Módulos Vivos) ---
function getDynamicGreeting() {
    const greetingEl = document.getElementById('dynamic-greeting-message');
    if (!greetingEl) return;
    
    const username = document.querySelector('.navbar-text')?.textContent.trim() || 'Usuario';
    const hour = new Date().getHours();
    let greeting = '¡Hola';
    let icon = '👋';
    
    if (hour < 12) {
        greeting = '¡Buenos días';
        icon = '☀️';
    } else if (hour < 18) {
        greeting = '¡Buenas tardes';
        icon = '😎';
    } else {
        greeting = '¡Buenas noches';
        icon = '🌙';
    }
    greetingEl.innerHTML = `${greeting}, <strong>${escapeHtmlForDisplay(username)}</strong>! ${icon}`;
}

async function fetchHomeStats() {
    try {
        const response = await fetch('api_home_stats.php');
        if (!response.ok) {
            if (response.status === 401) { window.location.href = 'login.php?error=Sesión+expirada.'; }
            throw new Error('Error de red al cargar estadísticas.');
        }
        const data = await response.json();
        if (data.success && data.stats) {
            localStorage.setItem('jumperCount', data.stats.total_jumpers);
            updateStatCard('stat-total-jumpers', data.stats.total_jumpers, true);
            updateRankCard(data.stats.total_jumpers);
        }
    } catch (error) {
        console.error("Error fetching home stats:", error);
    }
}

function updateStatCard(elementId, value, isCounter = false) {
    const el = document.getElementById(elementId);
    if (!el) return;
    
    if (isCounter && typeof value === 'number' && value > 0) {
        let start = 0;
        const end = value;
        if (start === end) { el.textContent = end; return; }
        const duration = 1500;
        let current = start;
        const increment = Math.ceil(end / (duration / 20));
        
        const timer = setInterval(() => {
            current += increment;
            if (current > end) { current = end; }
            el.textContent = current;
            if (current == end) { clearInterval(timer); }
        }, 20);
    } else {
        el.textContent = value;
    }
}


// --- Lógica específica para Meinungsplatz ---
function initializeMeinungsplatzListeners() {
    const form = moduleContentContainer.querySelector('#meinungsplatz-form');
    if (!form || form.dataset.initialized === 'true') { return; }
    form.dataset.initialized = 'true';

    const urlTextarea = form.querySelector('#url_textarea');
    const projektnummerInput = form.querySelector('#projektnummer_input');
    const resultContainer = moduleContentContainer.querySelector('#result-container');
    const generateBtn = form.querySelector('#generate-btn');
    const btnText = generateBtn ? generateBtn.querySelector('.btn-text') : null;
    const btnSpinner = generateBtn ? generateBtn.querySelector('.spinner-border') : null;
    const clearBtn = moduleContentContainer.querySelector('#meinungsplatz-clear-btn');

    if (!urlTextarea || !projektnummerInput || !resultContainer || !generateBtn || !btnText || !btnSpinner || !clearBtn) {
         console.error("Error: Missing Meinungsplatz form elements."); return;
    }

    const handleMeinungsplatzSubmit = async (e) => {
         e.preventDefault();
         generateBtn.disabled = true; btnText.classList.add('loading'); btnSpinner.classList.remove('d-none'); resultContainer.style.display = 'none'; clearBtn.classList.add('d-none');
         try {
             const response = await fetch('api_generate.php', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ urls: urlTextarea.value, projektnummer: projektnummerInput.value }) });
             const data = await response.json();
             
             if (response.status === 401) {
                window.location.href = 'login.php?error=Sesión+expirada+o+inválida.';
                return;
             }

             if (response.ok && data.success) {
                 showSuccessResult(data);
                 saveToRecentHistory(`MP: ${data.projektnummer}`, data.jumper);
                 checkJumperGamification();
             } else if (data.error_type === 'subid_not_found') {
                 showErrorModal(data);
             } else {
                  showErrorResultAsAlert(data.message || 'Error al generar.');
                  showToast(data.message || 'Error al generar.', 'warning');
             }
         } catch (error) {
             console.error("Error Meinungsplatz fetch:", error);
             const errorMsg = `Error de conexión: ${escapeHtmlForDisplay(error.message)}`;
             showErrorResultAsAlert(errorMsg);
             clearBtn.classList.remove('d-none');
             showToast('Error de conexión al generar.', 'danger');
         } finally {
             generateBtn.disabled = false; btnText.classList.remove('loading'); btnSpinner.classList.add('d-none');
         }
    };

    const handleMeinungsplatzClear = () => {
         if (urlTextarea) urlTextarea.value = '';
         if (projektnummerInput) projektnummerInput.value = '';
         if (resultContainer) { resultContainer.style.display = 'none'; resultContainer.innerHTML = ''; }
         if (clearBtn) clearBtn.classList.add('d-none');
         if (urlTextarea) urlTextarea.focus();
    };

    form.removeEventListener('submit', handleMeinungsplatzSubmit);
    form.addEventListener('submit', handleMeinungsplatzSubmit);
    clearBtn.removeEventListener('click', handleMeinungsplatzClear);
    clearBtn.addEventListener('click', handleMeinungsplatzClear);

    function showSuccessResult(data) {
        const template = document.getElementById('success-template'); if (!template) return;
        const content = template.content.cloneNode(true);
        
        const link = data.jumper;
        const linkForJs = escapeJsString(link);

        const jumperLinkEl = content.querySelector('.jumper-link');
        const copyBtnEl = content.querySelector('.btn-copy-jumper');
        const testBtnEl = content.querySelector('.jumper-link-test-btn');
        
        if (jumperLinkEl) { jumperLinkEl.href = link; jumperLinkEl.textContent = link; }
        if (testBtnEl) { testBtnEl.href = link; }
        if (copyBtnEl) { copyBtnEl.setAttribute('onclick', `copyJumper('${linkForJs}', this)`); }

        const subidDisplayEl = content.querySelector('.subid-display');
        if(subidDisplayEl) { subidDisplayEl.textContent = data.subid; }
        
        resultContainer.innerHTML = '';
        resultContainer.appendChild(content);
        resultContainer.style.display = 'block';
        clearBtn.classList.remove('d-none');
        initRatingSystem(data.subid, resultContainer);
    }
    
    function showErrorModal(data) {
        if (!subidErrorModal) {
             console.error("subidErrorModal instance is missing!");
             showErrorResultAsAlert(data.message || 'Error Modal no encontrado.');
             return;
        }
        const msgElement = document.getElementById('modal-error-message');
        const projektInput = document.getElementById('modal-add-projektnummer');
        const subidInput = document.getElementById('modal-add-new-subid');

        if(msgElement) msgElement.innerHTML = data.message;
        if(projektInput) projektInput.value = data.projektnummer;
        if(subidInput) subidInput.value = '';

        const addBtn = document.getElementById('modal-add-subid-btn');
        if (addBtn) {
            addBtn.disabled = false;
            const btnText = addBtn.querySelector('.btn-text');
            const spinner = addBtn.querySelector('.spinner-border');
            if (btnText) btnText.classList.remove('d-none');
            if (spinner) spinner.classList.add('d-none');
        }
        
        subidErrorModal.show();
        clearBtn.classList.remove('d-none');
    }

     function showErrorResultAsAlert(message) {
        resultContainer.innerHTML = `<div class="alert alert-danger">${escapeHtmlForDisplay(message)}</div>`;
        resultContainer.style.display = 'block';
        clearBtn.classList.remove('d-none');
    }

    function renderComments(comments, context) {
        const commentListContainer = context.querySelector('#comment-list-container');
        if (!commentListContainer) { console.warn("Contenedor #comment-list-container no encontrado."); return; }
        if (!comments || comments.length === 0) {
            commentListContainer.innerHTML = '<p class="text-muted small text-center mt-3">Aún no hay comentarios para este SubID.</p>';
            return;
        }
        let commentsHtml = '<h6 class="mb-3 mt-4">Comentarios Recientes:</h6><ul class="list-group list-group-flush small">';
        comments.forEach(comment => {
            let dateString = 'Fecha desconocida';
            try {
                 dateString = new Date(comment.created_at.replace(' ', 'T') + 'Z').toLocaleString('es-VE', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true });
                 if (dateString === "Invalid Date") { dateString = comment.created_at; }
            } catch(e) { dateString = comment.created_at || '...'; }
            commentsHtml += `
                <li class="list-group-item px-0 py-2">
                    <div class="d-flex justify-content-between">
                        <strong>${escapeHtmlForDisplay(comment.username || 'Usuario')}</strong>
                        <small class="text-muted">${escapeHtmlForDisplay(dateString)}</small>
                    </div>
                    <p class="mb-0 mt-1" style="white-space: pre-wrap; word-wrap: break-word;">${escapeHtmlForDisplay(comment.comment)}</p>
                </li>`;
        });
        commentsHtml += '</ul>';
        commentListContainer.innerHTML = commentsHtml;
    }

    function initRatingSystem(subid, context) {
        const ratingSection = context.querySelector('.rating-section');
        if (!ratingSection) return;
        const ratingBtns = ratingSection.querySelectorAll('.rating-btn');
        const submitBtn = ratingSection.querySelector('#submit-rating-btn');
        const commentTextarea = ratingSection.querySelector('#comment-textarea');
        const positiveCountEl = ratingSection.querySelector('.positive-count');
        const negativeCountEl = ratingSection.querySelector('.negative-count');
        let currentRating = null;

        if(!ratingBtns.length || !submitBtn || !commentTextarea || !positiveCountEl || !negativeCountEl) {
             console.error("Missing elements for rating system init."); return;
        }

        fetch(`api_rate.php?subid=${subid}`)
            .then(r => {
                if (r.status === 401) { window.location.href = 'login.php?error=Sesión+expirada.'; }
                if (!r.ok) { throw new Error(`HTTP error ${r.status}`); }
                return r.json();
            })
            .then(data => {
                if(data.success) {
                    if (data.ratings) {
                        positiveCountEl.textContent = data.ratings.positive;
                        negativeCountEl.textContent = data.ratings.negative;
                    }
                    if (data.comments) {
                        renderComments(data.comments, ratingSection);
                    }
                } else {
                    console.warn("API returned success:false on GET ratings", data.message);
                    showToast(data.message || 'Error al cargar ratings.', 'warning');
                }
            }).catch(e => {
                 console.error("Error fetching initial ratings/comments:", e);
                 showToast('Error de red al cargar ratings: ' + e.message, 'danger');
            });

        ratingBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                ratingBtns.forEach(b => b.classList.remove('btn-light'));
                btn.classList.add('btn-light');
                currentRating = btn.dataset.rating;
            });
        });

        submitBtn.addEventListener('click', async () => {
            if (currentRating === null && !commentTextarea.value.trim()) { 
                showToast('Debes seleccionar una calificación o escribir un comentario.', 'warning'); 
                return; 
            }
            if (currentRating === null) {
                showToast('Por favor, selecciona una calificación (pulgar arriba o abajo).', 'warning');
                return;
            }
            submitBtn.disabled = true;
            const originalText = submitBtn.textContent;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Enviando...';
            try {
                const response = await fetch('api_rate.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({ subid: subid, rating: currentRating, comment: commentTextarea.value })
                });
                if (response.status === 401) {
                    window.location.href = 'login.php?error=Sesión+expirada+o+inválida.';
                    return;
                }
                const data = await response.json();
                if (response.ok && data.success) {
                    if (data.ratings) {
                        positiveCountEl.textContent = data.ratings.positive;
                        negativeCountEl.textContent = data.ratings.negative;
                    }
                    if (data.comments) {
                        renderComments(data.comments, ratingSection);
                    }
                    ratingBtns.forEach(b => b.disabled = true);
                    commentTextarea.disabled = true;
                    submitBtn.textContent = '¡Gracias!';
                    submitBtn.classList.replace('btn-primary', 'btn-success');
                    showToast(data.message || '¡Gracias por calificar!', 'success', 3000);
                } else {
                    throw new Error(data.message || 'Respuesta no exitosa');
                }
            } catch (error) {
                 console.error("Error submitting rating:", error);
                 showToast('Error al guardar calificación: ' + error.message, 'danger');
                 submitBtn.disabled = false;
                 submitBtn.textContent = originalText;
            }
        });

        const hideBtn = ratingSection.querySelector('#hide-rating-btn');
        if (hideBtn) { hideBtn.addEventListener('click', () => ratingSection.style.display = 'none'); }
    } // Fin initRatingSystem
    
} // Fin initializeMeinungsplatzListeners

// *** CORRECCIÓN: Mover esta función al alcance global ***
function initializeSubidModalListeners(modalInstance) {
    const modalForm = document.getElementById('modal-add-subid-form');
    const cancelBtn = document.getElementById('modal-cancel-add-subid-btn');
    const closeBtn = document.getElementById('modal-close-btn');
    if (!modalForm || !cancelBtn || !modalInstance || !closeBtn) {
        // No imprimir error, ya que este modal solo existe en index.php
        return;
    }

    const clearMpForm = () => {
         const clearBtn = moduleContentContainer.querySelector('#meinungsplatz-clear-btn');
         if(clearBtn) clearBtn.click();
    };
    
    cancelBtn.addEventListener('click', clearMpForm);
    closeBtn.addEventListener('click', clearMpForm);

    modalForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const projektnummer = document.getElementById('modal-add-projektnummer').value;
        const newSubid = document.getElementById('modal-add-new-subid').value;
        const submitBtn = document.getElementById('modal-add-subid-btn');
        const btnText = submitBtn ? submitBtn.querySelector('.btn-text') : null;
        const spinner = submitBtn ? submitBtn.querySelector('.spinner-border') : null;

        if(!projektnummer || !newSubid || !submitBtn) return;
        
        submitBtn.disabled = true;
        if (btnText) btnText.classList.add('d-none');
        if (spinner) spinner.classList.remove('d-none');

        try {
             const response = await fetch('api_add_subid.php', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ projektnummer, new_subid: newSubid }) });
             if (response.status === 401) {
                window.location.href = 'login.php?error=Sesión+expirada+o+inválida.';
                return;
             }
             const data = await response.json();
             if (!response.ok || !data.success) {
                throw new Error(data.message || 'Error del servidor');
             }
             showToast(data.message || 'SubID añadido. Regenerando...', 'success', 3000);
             modalInstance.hide();
             const mainMpForm = document.getElementById('meinungsplatz-form');
             if(mainMpForm) mainMpForm.dispatchEvent(new Event('submit'));
        } catch (error) {
             console.error('Error al añadir SubID desde modal:', error);
             showToast('Error al añadir SubID: ' + error.message, 'danger');
             submitBtn.disabled = false;
             if (btnText) btnText.classList.remove('d-none');
             if (spinner) spinner.classList.add('d-none');
        }
    });
} // Fin initializeSubidModalListeners

// --- Lógica de Modo Oscuro ---
function initializeDarkMode() {
    const toggleButton = document.getElementById('dark-mode-toggle');
    // *** CORRECCIÓN: Comprobar si el botón existe ***
    if (!toggleButton) {
        // No estamos en login.php o register.php (o go.php)
        // Pero SÍ aplicar el tema si está guardado
        const currentTheme = localStorage.getItem('theme');
         if (currentTheme === 'dark') {
            document.body.setAttribute('data-theme', 'dark');
        }
        return; 
    }
    
    const icon = toggleButton.querySelector('i');
    
    const currentTheme = localStorage.getItem('theme');
    if (currentTheme === 'dark') {
        document.body.setAttribute('data-theme', 'dark');
        icon.classList.remove('bi-moon-stars-fill');
        icon.classList.add('bi-sun-fill');
    } else {
        document.body.removeAttribute('data-theme');
        icon.classList.remove('bi-sun-fill');
        icon.classList.add('bi-moon-stars-fill');
    }
    
    toggleButton.addEventListener('click', () => {
        if (document.body.hasAttribute('data-theme')) {
            document.body.removeAttribute('data-theme');
            localStorage.removeItem('theme');
            icon.classList.remove('bi-sun-fill');
            icon.classList.add('bi-moon-stars-fill');
        } else {
            document.body.setAttribute('data-theme', 'dark');
            localStorage.setItem('theme', 'dark');
            icon.classList.remove('bi-moon-stars-fill');
            icon.classList.add('bi-sun-fill');
        }
    });
}
initializeDarkMode(); // Ejecutar al cargar el script

// --- Lógica de Historial Reciente ---
const MAX_HISTORY = 5;
function getRecentHistory() {
    return JSON.parse(localStorage.getItem('jumperHistory') || '[]');
}
function saveToRecentHistory(name, link) {
    let history = getRecentHistory();
    history.unshift({ name, link });
    if (history.length > MAX_HISTORY) {
        history = history.slice(0, MAX_HISTORY);
    }
    localStorage.setItem('jumperHistory', JSON.stringify(history));
    buildRecentHistory();
}
function buildRecentHistory() {
    const listEl = document.getElementById('recent-history-list');
    if (!listEl) return;
    
    const history = getRecentHistory();
    if (history.length === 0) {
        listEl.innerHTML = '<li class="list-group-item text-muted small">No hay jumpers recientes.</li>';
        return;
    }
    
    listEl.innerHTML = '';
    history.forEach(item => {
        const linkForJs = escapeJsString(item.link);
        const shortLink = item.link.length > 30 ? item.link.substring(0, 30) + '...' : item.link;
        listEl.innerHTML += `
            <li class="list-group-item">
                <div class="history-item-label" title="${escapeHtml(item.link)}">
                    <strong>${escapeHtmlForDisplay(item.name)}:</strong>
                    ${escapeHtmlForDisplay(shortLink)}
                </div>
                <button class="btn btn-sm btn-outline-primary btn-copy-history" onclick="copyJumper('${linkForJs}', this)" title="Copiar">
                    <i class="bi bi-clipboard-check-fill"></i>
                </button>
            </li>
        `;
    });
}
// --- FIN Lógica Historial ---

// --- Lógica de Gamificación ---
const RANKS = {
    novice: { name: 'Jumper Novato', icon: '🥉', min: 0, class: 'rank-novice' },
    pro: { name: 'Jumper Pro', icon: '🥈', min: 21, class: 'rank-pro' },
    master: { name: 'Jumper Maestro', icon: '🥇', min: 101, class: 'rank-maestro' }
};

function getRank(count) {
    if (count >= RANKS.master.min) return RANKS.master;
    if (count >= RANKS.pro.min) return RANKS.pro;
    return RANKS.novice;
}

function updateRankCard(count) {
    const rankCard = document.getElementById('jumper-rank-card');
    if (!rankCard) return;
    
    const rank = getRank(count);
    rankCard.querySelector('.rank-icon').textContent = rank.icon;
    const rankNameEl = rankCard.querySelector('.rank-name');
    rankNameEl.textContent = rank.name;
    rankNameEl.className = 'rank-name ' + rank.class;
}

function checkJumperGamification() {
    let currentCount = parseInt(localStorage.getItem('jumperCount') || '0', 10);
    const oldRank = getRank(currentCount);
    
    const newCount = currentCount + 1;
    localStorage.setItem('jumperCount', newCount);
    
    const newRank = getRank(newCount);
    
    const jumboValue = document.getElementById('stat-total-jumpers');
    if (jumboValue) {
        updateStatCard('stat-total-jumpers', newCount, true);
        updateRankCard(newCount);
    }
    
    if (oldRank.name !== newRank.name) {
        showLevelUpModal(newRank);
    }
}

function showLevelUpModal(rank) {
    if (!levelUpModal) {
        const modalEl = document.getElementById('levelUpModal');
        if (modalEl) levelUpModal = new bootstrap.Modal(modalEl);
        else return;
    }
    
    const iconEl = document.getElementById('levelUpIcon');
    const nameEl = document.getElementById('levelUpRankName');
    
    if (iconEl) iconEl.textContent = rank.icon;
    if (nameEl) {
        nameEl.textContent = rank.name;
        nameEl.className = 'level-up-rank ' + rank.class;
    }
    
    levelUpModal.show();
    
    const confettiContainer = document.querySelector('.confetti-container');
    if (confettiContainer) {
        confettiContainer.innerHTML = '';
        for (let i = 0; i < 50; i++) {
            const confetti = document.createElement('div');
            confetti.className = 'confetti';
            confetti.style.left = `${Math.random() * 100}%`;
            confetti.style.animation = `confetti-fall ${Math.random() * 3 + 2}s linear ${Math.random() * 2}s infinite`;
            confetti.style.backgroundColor = `hsl(${Math.random() * 360}, 100%, 50%)`;
            confettiContainer.appendChild(confetti);
        }
    }
}
// --- FIN Lógica Gamificación ---

// *** NUEVO: Lógica para la página de Ranking ***
async function fetchRankingData() {
    const rankingList = document.getElementById('ranking-list');
    if (!rankingList) {
        console.error("No se encontró el elemento #ranking-list.");
        return;
    }

    try {
        const response = await fetch('api_ranking.php');
        if (!response.ok) {
            if (response.status === 401) { window.location.href = 'login.php?error=Sesión+expirada.'; }
            throw new Error('Error de red al cargar el ranking.');
        }
        const data = await response.json();
        
        if (data.success && data.ranking) {
            rankingList.innerHTML = ''; // Limpiar skeletons
            const ranking = data.ranking;
            
            if (ranking.length === 0) {
                 rankingList.innerHTML = '<li class="pyramid-item text-muted">Aún no hay datos de ranking. ¡Empieza a añadir SubIDs!</li>';
                 return;
            }

            // Construir la pirámide
            ranking.forEach((user, index) => {
                rankingList.innerHTML += buildPyramidRow(user, index);
            });
            
        } else {
            rankingList.innerHTML = `<li class="pyramid-item text-danger">Error al cargar el ranking: ${data.message}</li>`;
        }

    } catch (error) {
        console.error("Error fetching ranking data:", error);
        rankingList.innerHTML = `<li class="pyramid-item text-danger">Error de conexión al cargar el ranking.</li>`;
    }
}

function buildPyramidRow(user, index) {
    let rankClass = '';
    if (index === 0) rankClass = 'rank-1';
    if (index === 1) rankClass = 'rank-2';
    if (index === 2) rankClass = 'rank-3';

    // Calcular el ancho de la barra (ej. 100% para el #1, 90% para el #2, etc.)
    const widthPercent = 100 - (index * 10);
    
    return `
        <li class="pyramid-item ${rankClass}" style="width: ${widthPercent}%; animation-delay: ${index * 100}ms">
            <span class="pyramid-rank">#${user.rank}</span>
            <img src="${user.avatar_url}" alt="${user.username}" class="pyramid-avatar">
            <span class="pyramid-username">${escapeHtmlForDisplay(user.username)}</span>
            <span class="pyramid-count">${user.count}</span>
        </li>
    `;
}
// *** FIN Lógica Ranking ***

// *** CORRECCIÓN: Inicializar modales globales al cargar el script ***
if (subidErrorModalEl) {
    subidErrorModal = new bootstrap.Modal(subidErrorModalEl);
    initializeSubidModalListeners(subidErrorModal);
}
if (levelUpModalEl) {
    levelUpModal = new bootstrap.Modal(levelUpModalEl);
}