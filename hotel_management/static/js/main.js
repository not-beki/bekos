document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Date picker initialization for booking forms
    const today = new Date().toISOString().split('T')[0];
    const checkInInputs = document.querySelectorAll('input[name="check_in"]');
    const checkOutInputs = document.querySelectorAll('input[name="check_out"]');
    
    checkInInputs.forEach(input => {
        if (input.type === 'date') {
            input.min = today;
        }
    });

    checkOutInputs.forEach(input => {
        if (input.type === 'date') {
            const checkIn = input.closest('form').querySelector('input[name="check_in"]');
            if (checkIn) {
                checkIn.addEventListener('change', function() {
                    input.min = this.value;
                });
            }
        }
    });

    // Form validation
    const forms = document.querySelectorAll('.needs-validation');
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });

    // Auto-dismiss flash messages after 5 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});