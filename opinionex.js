// opinionex.js
(function(){
  'use strict';

  const inputUrls = document.getElementById('input_urls');
  const projektnummerEl = document.getElementById('projektnummer');
  const btnGenerate = document.getElementById('btn-generate');
  const formMessage = document.getElementById('form-message');
  const resultCard = document.getElementById('resultCard');
  const resultUrlEl = document.getElementById('resultUrl');
  const btnCopy = document.getElementById('btn-copy');
  const btnOpen = document.getElementById('btn-open');
  const historyList = document.getElementById('historyList');
  const toastContainer = document.getElementById('toastContainer');
  const fab = document.getElementById('fab');

  const history = [];

  function showToast(msg, timeout=3000){
    const t = document.createElement('div');
    t.className = 'toast';
    t.textContent = msg;
    toastContainer.appendChild(t);
    // trigger fade-in
    requestAnimationFrame(()=> t.style.opacity = '1');
    setTimeout(()=> {
      t.style.opacity = '0';
      t.addEventListener('transitionend', ()=> t.remove(), { once: true });
    }, timeout);
  }

  function validateProjektnummer(v){
    return /^\d{5,6}$/.test(v);
  }

  function extractFirst15DigitIdFromLines(text){
    const lines = text.split(/\r?\n/).map(s=>s.trim()).filter(Boolean).slice(0,50);
    for (const line of lines){
      try {
        const u = new URL(line);
        if (u.search){
          const params = new URLSearchParams(u.search);
          for (const [k,v] of params) {
            if (/^\d{15}$/.test(v)) return v;
          }
        }
      } catch(e){}
      const m = line.match(/[?&](?:m|UserID|uid|id)=([0-9]{15})(?:&|$)/i);
      if (m) return m[1];
    }
    return null;
  }

  async function postGenerate(formData){
    try {
      btnGenerate.disabled = true;
      const originalText = btnGenerate.textContent;
      btnGenerate.textContent = 'Generando...';
      formMessage.hidden = true;

      const resp = await fetch('api_generate_opinionex.php', {
        method: 'POST',
        body: new URLSearchParams(formData)
      });

      const data = await resp.json();
      if (!resp.ok) {
        const msg = data && data.message ? data.message : 'Error del servidor';
        formMessage.textContent = msg;
        formMessage.hidden = false;
        showToast(msg);
        return null;
      }
      return data;
    } catch (e){
      console.error(e);
      formMessage.textContent = 'Error de red al conectar con el servidor.';
      formMessage.hidden = false;
      showToast('Error de red');
      return null;
    } finally {
      btnGenerate.disabled = false;
      btnGenerate.textContent = 'Generar Jumper';
    }
  }

  function updateResult(jumper){
    resultUrlEl.textContent = jumper;
    btnOpen.href = jumper;
    resultCard.style.display = 'block';
    resultCard.style.opacity = '0';
    resultCard.style.transform = 'translateY(10px)';
    requestAnimationFrame(()=>{
      resultCard.style.transition = 'opacity 260ms ease, transform 260ms ease';
      resultCard.style.opacity = '1';
      resultCard.style.transform = 'translateY(0)';
    });
  }

  btnGenerate.addEventListener('click', async () => {
    formMessage.hidden = true;
    const urls = inputUrls.value.trim();
    const projektnummer = projektnummerEl.value.trim();

    if (!urls) { formMessage.textContent = 'Pega al menos una URL.'; formMessage.hidden=false; showToast('Pega al menos una URL'); return; }
    if (!validateProjektnummer(projektnummer)) { formMessage.textContent = 'Projektnummer inválido (5 o 6 dígitos).'; formMessage.hidden=false; showToast('Projektnummer inválido'); return; }

    const foundId = extractFirst15DigitIdFromLines(urls);
    if (!foundId) {
      formMessage.textContent = 'No se encontró un ID de usuario de 15 dígitos en las URLs. Revisa la entrada.';
      formMessage.hidden=false; showToast('ID de usuario no encontrado');
      return;
    }

    const form = { input_url_opinion: urls, projektnummer: projektnummer };
    const data = await postGenerate(form);
    if (data && data.success && data.jumper) {
      updateResult(data.jumper);
      history.unshift({ jumper: data.jumper, at: new Date().toISOString() });
      renderHistory();
      showToast('Jumper generado', 2000);
    }
  });

  btnCopy && btnCopy.addEventListener('click', async () => {
    try {
      const text = resultUrlEl.textContent;
      if (!navigator.clipboard) { showToast('Navegador sin API de portapapeles', 2500); return; }
      await navigator.clipboard.writeText(text);
      showToast('¡Enlace copiado!', 1500);
      btnCopy.textContent = 'Copiado';
      setTimeout(()=> btnCopy.textContent = 'Copiar', 1400);
    } catch (e) {
      console.error(e);
      showToast('Error al copiar', 2000);
    }
  });

  function renderHistory(){
    historyList.innerHTML = '';
    for (const item of history.slice(0,10)){
      const div = document.createElement('div');
      div.className = 'history-item';
      div.innerHTML = `<div class="small text-muted">${new Date(item.at).toLocaleString()}</div><div class="history-jumper">${item.jumper}</div><div><button class="btn small-btn" data-jump="${item.jumper}">Copiar</button></div>`;
      historyList.appendChild(div);
      const btn = div.querySelector('button');
      btn && btn.addEventListener('click', (e)=>{
        const j = e.currentTarget.getAttribute('data-jump');
        navigator.clipboard?.writeText(j).then(()=> showToast('Copiado del historial',1200));
      });
    }
  }

  fab && fab.addEventListener('click', ()=>{
    const menu = [
      {label:'Generar Meinungsplatz', fn: ()=> { inputUrls.focus(); }},
      {label:'Limpiar formulario', fn: ()=> { inputUrls.value=''; projektnummerEl.value=''; showToast('Formulario limpiado'); }},
    ];
    const choice = prompt('Acciones rápidas:\n1) ' + menu.map((m,i)=>`${i+1}) ${m.label}`).join('\n'));
    const idx = parseInt(choice) - 1;
    if (!isNaN(idx) && menu[idx]) menu[idx].fn();
  });

  const btnBack = document.getElementById('btn-back');
  btnBack && btnBack.addEventListener('click', ()=> { history.back(); });

  try {
    const saved = JSON.parse(localStorage.getItem('op_ex_history') || '[]');
    if (Array.isArray(saved)) { history.push(...saved); renderHistory(); }
    window.addEventListener('beforeunload', ()=> localStorage.setItem('op_ex_history', JSON.stringify(history.slice(0,50))));
  } catch(e){}
})();