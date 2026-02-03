// Main JavaScript file for Photo Share app
// Most functionality is inline in templates for simplicity

document.addEventListener('DOMContentLoaded', function() {
    // Auto-hide flash messages after 5 seconds
    const flashMessages = document.querySelectorAll('.flash');
    flashMessages.forEach(function(flash) {
        setTimeout(function() {
            flash.style.opacity = '0';
            flash.style.transition = 'opacity 0.5s';
            setTimeout(function() {
                flash.remove();
            }, 500);
        }, 5000);
    });
});
