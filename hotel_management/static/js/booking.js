document.addEventListener('DOMContentLoaded', function() {
    // Room booking date validation
    const checkIn = document.getElementById('check_in');
    const checkOut = document.getElementById('check_out');
    
    if (checkIn && checkOut) {
        const today = new Date().toISOString().split('T')[0];
        checkIn.min = today;
        
        checkIn.addEventListener('change', function() {
            checkOut.min = this.value;
            if (checkOut.value && checkOut.value < this.value) {
                checkOut.value = '';
            }
        });
        
        checkOut.addEventListener('change', function() {
            if (checkIn.value && this.value <= checkIn.value) {
                alert('Check-out date must be after check-in date');
                this.value = '';
            }
        });
    }

    // Calculate price based on dates
    const calculatePrice = function() {
        const roomPrice = parseFloat(document.getElementById('room_price').value);
        const checkInDate = new Date(checkIn.value);
        const checkOutDate = new Date(checkOut.value);
        
        if (checkIn.value && checkOut.value && checkOutDate > checkInDate) {
            const nights = (checkOutDate - checkInDate) / (1000 * 60 * 60 * 24);
            document.getElementById('total_price').value = (roomPrice * nights).toFixed(2);
        }
    };

    if (checkIn && checkOut) {
        checkIn.addEventListener('change', calculatePrice);
        checkOut.addEventListener('change', calculatePrice);
    }
});