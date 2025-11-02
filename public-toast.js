// public-toast.js (v2 - Diseño Alusinante)

document.addEventListener('DOMContentLoaded', () => {
    let activityList = [];
    let toastInterval;
    
    // Función para crear el toast
    function showActivityToast(user, message) {
        const toastContainer = document.getElementById('public-toast-container');
        if (!toastContainer) {
            console.error('Error: Contenedor #public-toast-container no encontrado.');
            return; 
        }

        const toastId = 'toast-' + Date.now();
        // *** NUEVO HTML para el Toast Llamativo ***
        const toastHTML = `
            <div id="${toastId}" class="toast live-toast" role="alert" aria-live="assertive" aria-atomic="true" data-bs-delay="5000">
                <div class="toast-body">
                    <div class="live-toast-icon">
                        <i class="bi bi-graph-up-arrow"></i>
                    </div>
                    <div class="live-toast-text">
                        <strong>${user}</strong> ${message}
                    </div>
                    <small class="live-toast-time">justo ahora</small>
                </div>
            </div>
        `;
        
        toastContainer.insertAdjacentHTML('beforeend', toastHTML);
        const toastElement = document.getElementById(toastId);
        const toast = new bootstrap.Toast(toastElement);
        toast.show();
        
        // Limpiar el toast del DOM después de que se oculte
        toastElement.addEventListener('hidden.bs.toast', () => toastElement.remove());
    }

    // Función para iniciar el ciclo
    function startToastLoop() {
        if (toastInterval) clearInterval(toastInterval);
        
        toastInterval = setInterval(() => {
            if (activityList.length === 0) return;
            
            const randomIndex = Math.floor(Math.random() * activityList.length);
            const activity = activityList[randomIndex];
            
            showActivityToast(activity.user, activity.message);
            
        }, Math.random() * (10000 - 6000) + 6000); // Aleatorio entre 6 y 10 segundos
    }

    // Función para buscar los datos de la API
    async function fetchActivityData() {
        try {
            const response = await fetch('api_public_activity.php');
            if (!response.ok) return;
            
            const data = await response.json();
            if (data.success && data.activities.length > 0) {
                activityList = data.activities;
                
                // Mostrar uno de inmediato (después de unos segundos)
                const randomIndex = Math.floor(Math.random() * activityList.length);
                const activity = activityList[randomIndex];
                setTimeout(() => {
                   showActivityToast(activity.user, activity.message);
                }, 3000); // Esperar 3 segundos en la carga de la página
                
                startToastLoop();
            }
        } catch (error) {
            console.error('Error fetching public activity:', error);
        }
    }

    // Iniciar todo
    fetchActivityData();
});