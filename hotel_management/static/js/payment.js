document.addEventListener('DOMContentLoaded', function() {
    // Handle payment method selection
    const paymentMethods = document.querySelectorAll('input[name="payment_method"]');
    const paymentDetails = document.getElementById('payment-details');
    
    paymentMethods.forEach(method => {
        method.addEventListener('change', function() {
            // Show/hide payment details based on selection
            const methodName = this.value;
            const allDetails = paymentDetails.querySelectorAll('.method-details');
            
            allDetails.forEach(detail => {
                detail.style.display = 'none';
            });
            
            const selectedDetail = paymentDetails.querySelector(`.${methodName}-details`);
            if (selectedDetail) {
                selectedDetail.style.display = 'block';
            }
        });
    });

    // Simulate payment processing
    const paymentForm = document.getElementById('payment-form');
    if (paymentForm) {
        paymentForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            
            // Simulate processing
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
            
            setTimeout(() => {
                // In a real app, this would be an actual payment API call
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
                
                // Redirect to payment status page
                window.location.href = "{{ url_for('payment_status', booking_id=booking.id) }}";
            }, 2000);
        });
    }
});