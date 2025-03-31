from flask import Flask, Response, render_template, redirect, url_for, session, flash, request, abort, jsonify, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, validators
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import re
import os
import base64
import json
import hashlib
import hmac
import time
import requests
from dotenv import load_dotenv
from cryptography.fernet import Fernet


# Initialize Flask app
load_dotenv()
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///hotel.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Payment Configuration
app.config['TELEBIRR_CONFIG'] = {
    'merchant_app_id': os.environ.get('TELEBIRR_MERCHANT_APP_ID'),
    'fabric_app_id': os.environ.get('TELEBIRR_FABRIC_APP_ID'),
    'short_code': os.environ.get('TELEBIRR_SHORT_CODE'),
    'app_secret': os.environ.get('TELEBIRR_APP_SECRET'),
    'public_key': os.environ.get('TELEBIRR_PUBLIC_KEY').replace('\\n', '\n'),
    'private_key': os.environ.get('TELEBIRR_PRIVATE_KEY').replace('\\n', '\n'),
    'api_base_url': os.environ.get('TELEBIRR_API_BASE_URL', 'https://api.telebirr.com')
}

app.config['CBE_API_KEY'] = os.environ.get('CBE_API_KEY', 'test_key')
app.config['PAYMENT_CALLBACK_URL'] = os.environ.get('PAYMENT_CALLBACK_URL', 'http://localhost:5000/payment/callback')
app.config['CREDENTIALS_KEY'] = os.environ.get('CREDENTIALS_KEY', Fernet.generate_key().decode())

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

class TelebirrPayment:
    @classmethod
    def get_active_config(cls):
        return current_app.config['TELEBIRR_CONFIG']
    
    @staticmethod
    def generate_signature(params, app_secret):
        """Secure signature generation with constant-time comparison"""
        sorted_params = sorted(params.items())
        sign_str = '&'.join([f"{k}={v}" for k, v in sorted_params])
        return hashlib.sha256((sign_str + app_secret).encode()).hexdigest()

    @staticmethod
    def encrypt_with_public_key(data, public_key):
        """Safe encryption with chunking for large data"""
        rsa_key = RSA.importKey(public_key)
        cipher = PKCS1_v1_5.new(rsa_key)
        data_str = json.dumps(data)
        
        # Split into chunks of 200 bytes (for 2048-bit key)
        chunk_size = 200
        encrypted_chunks = []
        for i in range(0, len(data_str), chunk_size):
            chunk = data_str[i:i+chunk_size]
            encrypted_chunks.append(cipher.encrypt(chunk.encode()))
        
        return base64.b64encode(b''.join(encrypted_chunks)).decode()

    @classmethod
    def verify_callback_signature(cls, params, received_sign):
        """Secure signature verification"""
        config = cls.get_active_config()
        calculated_sign = cls.generate_signature(params, config['app_secret'])
        return hmac.compare_digest(calculated_sign, received_sign)

    @classmethod
    def generate_payment_request(cls, amount, out_trade_no, notify_url):
        """Generate complete payment request with versioning"""
        config = cls.get_active_config()
        
        params = {
            "appId": config['merchant_app_id'],
            "appKey": config['fabric_app_id'],
            "nonce": str(int(datetime.now().timestamp())),
            "timestamp": str(int(datetime.now().timestamp() * 1000)),
            "outTradeNo": out_trade_no,
            "subject": "Hotel Booking",
            "totalAmount": str(amount),
            "shortCode": config['short_code'],
            "notifyUrl": notify_url,
            "returnUrl": notify_url,
            "timeoutExpress": "30"
        }
        
        params['sign'] = cls.generate_signature(params, config['app_secret'])
        
        return {
            "url": f"{config['api_base_url']}/payment/create",
            "headers": {
                "appkey": config['fabric_app_id'],
                "sign": params['sign'],
                "content-type": "application/json",
                "X-Credential-Version": "v1"
            },
            "data": {
                "data": cls.encrypt_with_public_key(params, config['public_key'])
            }
        }

class ContactForm(FlaskForm):
    name = StringField('Name', [validators.InputRequired()])
    email = StringField('Email', [validators.InputRequired(), validators.Email()])
    subject = StringField('Subject', [validators.InputRequired()])
    message = TextAreaField('Message', [validators.InputRequired()])

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text)
    id_number = db.Column(db.String(50))
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    check_out_date = db.Column(db.DateTime)
    bookings = db.relationship('Booking', backref='customer', lazy=True)

class Query(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)
    
class RoomType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    base_price = db.Column(db.Float, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(100))
    rooms = db.relationship('Room', backref='room_type', lazy=True)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(10), unique=True, nullable=False)
    status = db.Column(db.String(20), default='Available')
    type_id = db.Column(db.Integer, db.ForeignKey('room_type.id'), nullable=False)
    bookings = db.relationship('Booking', backref='room', lazy=True)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    check_in = db.Column(db.DateTime, nullable=False)
    check_out = db.Column(db.DateTime, nullable=False)
    adults = db.Column(db.Integer, default=1)
    children = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='Pending')
    total_price = db.Column(db.Float, nullable=True)  # Changed to nullable
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    payment_status = db.Column(db.String(20), default='Unpaid')  # Add this line
    payments = db.relationship('Payment', backref='booking', lazy=True)  # Add this line

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('booking.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    method = db.Column(db.String(20))  # 'CBE', 'Telebirr'
    transaction_id = db.Column(db.String(100), unique=True)
    status = db.Column(db.String(20), default='Pending')  # Paid/Failed/Refunded
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    def generate_receipt(self):
        """Generate PDF receipt for the payment"""
        from flask_weasyprint import HTML, render_pdf
        
        customer = Customer.query.get(self.customer_id)
        booking = Booking.query.filter_by(id=self.booking_id).first() if self.booking_id else None
        
        html = render_template('receipt.html', 
                            payment=self,
                            customer=customer,
                            booking=booking)
        
        return render_pdf(HTML(string=html))

    @property
    def receipt_number(self):
        """Generate formatted receipt number"""
        return f"RC-{self.id:06d}-{self.timestamp.strftime('%Y%m')}"

class Staff(db.Model):
    staff_id = db.Column(db.Integer, primary_key=True)  # Changed from 'id' to 'staff_id'
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    position = db.Column(db.String(50))
    hire_date = db.Column(db.DateTime, default=datetime.utcnow)

    # At the TOP of your file (after imports but before routes)
def validate_config():
    """Validate Telebirr configuration"""
    required = ['merchant_app_id', 'fabric_app_id', 'app_secret', 'public_key']
    config = app.config['TELEBIRR_CONFIG']
    
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise RuntimeError(f"Missing Telebirr config: {', '.join(missing)}")
    
    try:
        RSA.importKey(config['public_key'])
    except (ValueError, IndexError) as e:
        raise RuntimeError(f"Invalid Telebirr public key: {str(e)}")

def initialize_database():
    """Initialize database tables and admin user"""
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@hotel.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
        print("Database initialized successfully")


def calculate_total_price(room_id, check_in, check_out):
    room = Room.query.get(room_id)
    duration = (check_out - check_in).days
    return room.room_type.base_price * duration

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def initialize_database():
    """Initialize the database with default data"""
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@hotel.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
        
        # Create default room types if not exist
        if not RoomType.query.first():
            room_types = [
                RoomType(name='Deluxe', description='Spacious room with city view', 
                        base_price=200, capacity=2, image='deluxe.jpg'),
                RoomType(name='Luxury', description='Premium suite with extra amenities', 
                        base_price=350, capacity=4, image='luxury.jpg'),
                RoomType(name='Standard', description='Comfortable budget-friendly room', 
                        base_price=100, capacity=2, image='standard.jpg')
            ]
            db.session.add_all(room_types)
        
        db.session.commit()

# Initialize the database
initialize_database()

# --------------------------
# Frontend Routes
# --------------------------
@app.after_request
def add_security_headers(response):
    if request.path.startswith('/payment/'):
        response.headers.update({
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'",
            'X-Credential-Version': "v1"
        })
    return response

# Config validation
@app.cli.command("init-db")
def init_db():
    """Initialize the database"""
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@hotel.com', is_admin=True)
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
    
    print("Database initialized")


@app.route('/')
def home():
    room_types = RoomType.query.all()
    return render_template('index.html', room_types=room_types)

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/about')
def about():
    return render_template('about.html')

def generate_telebirr_payment_request(entity, callback_url, amount, description):
    """Generate payment request for Telebirr"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    
    request_data = {
        "outTradeNo": f"TB-{timestamp}",
        "subject": description,
        "totalAmount": str(amount),
        "shortCode": app.config['TELEBIRR_SHORT_CODE'],
        "notifyUrl": callback_url,
        "returnUrl": callback_url,
        "timeoutExpress": "30",
        "nonce": timestamp,
        "timestamp": timestamp
    }
    
    # In production, you would encrypt this data with Telebirr's public key
    return {
        "data": request_data,
        "url": f"{app.config['TELEBIRR_API_BASE_URL']}/payment/create"
    }

@app.route('/room/<int:room_type_id>')
def room_details(room_type_id):
    room_type = RoomType.query.get_or_404(room_type_id)
    available_rooms = Room.query.filter_by(type_id=room_type.id, status='Available').all()
    return render_template('room_details.html', room_type=room_type, available_rooms=available_rooms)

# --------------------------
# Admin Authentication
# --------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']) and user.is_admin:
            session['admin_logged_in'] = True
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

# --------------------------
# Admin Dashboard
# --------------------------

@app.route('/admin/')
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    stats = {
         'paid_bookings': Booking.query.filter_by(payment_status='Paid').count(), 
        'total_bookings': Booking.query.count(),
        'available_rooms': Room.query.filter_by(status='Available').count(),
        'active_customers': Customer.query.filter(Customer.check_out_date.is_(None)).count(),
        'pending_requests': Booking.query.filter_by(status='Pending').count(),
        'total_revenue': db.session.query(db.func.sum(Booking.total_price)).filter(
            Booking.status == 'Completed').scalar() or 0
            
    }
    
    recent_bookings = Booking.query.order_by(Booking.created_at.desc()).limit(5).all()
    recent_customers = Customer.query.order_by(Customer.registration_date.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         stats=stats,
                         bookings=recent_bookings,
                         customers=recent_customers)

# --------------------------
# Customer Management
# --------------------------

@app.route('/admin/customers', methods=['GET', 'POST'])
@login_required
def manage_customers():
    if request.method == 'POST':
        customer = Customer(
            first_name=request.form['first_name'],
            last_name=request.form['last_name'],
            email=request.form['email'],
            phone=request.form['phone'],
            address=request.form.get('address', ''),
            id_number=request.form.get('id_number', '')
        )
        db.session.add(customer)
        db.session.commit()
        flash('Customer added successfully!', 'success')
        return redirect(url_for('manage_customers'))
    
    customers = Customer.query.order_by(Customer.registration_date.desc()).all()
    return render_template('admin/customers.html', customers=customers)

@app.route('/admin/customers/edit/<int:customer_id>', methods=['GET', 'POST'])
@login_required
def edit_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    if request.method == 'POST':
        customer.first_name = request.form['first_name']
        customer.last_name = request.form['last_name']
        customer.email = request.form['email']
        customer.phone = request.form['phone']
        customer.address = request.form.get('address', '')
        customer.id_number = request.form.get('id_number', '')
        db.session.commit()
        flash('Customer updated successfully!', 'success')
        return redirect(url_for('manage_customers'))
    return render_template('admin/edit_customer.html', customer=customer)

@app.route('/admin/customers/delete/<int:customer_id>', methods=['POST'])
@login_required
def delete_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    db.session.delete(customer)
    db.session.commit()
    flash('Customer deleted successfully', 'success')
    return redirect(url_for('manage_customers'))

@app.route('/admin/customers/checkout/<int:customer_id>', methods=['POST'])
@login_required
def checkout_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    customer.check_out_date = datetime.utcnow()
    db.session.commit()
    flash(f'{customer.first_name} has been checked out', 'success')
    return redirect(url_for('manage_customers'))

# --------------------------
# Room Management
# --------------------------

@app.route('/admin/room-types', methods=['GET', 'POST'])
@login_required
def manage_room_types():
    if request.method == 'POST':
        room_type = RoomType(
            name=request.form['name'],
            description=request.form.get('description', ''),
            base_price=float(request.form['base_price']),
            capacity=int(request.form['capacity']),
            image=request.form.get('image', 'default.jpg')
        )
        db.session.add(room_type)
        db.session.commit()
        flash('Room type added successfully!', 'success')
        return redirect(url_for('manage_room_types'))
    
    room_types = RoomType.query.all()
    return render_template('admin/room_types.html', room_types=room_types)

@app.route('/admin/room-types/delete/<int:type_id>', methods=['POST'])
@login_required
def delete_room_type(type_id):
    room_type = RoomType.query.get_or_404(type_id)
    
    # Check if there are rooms using this type
    if Room.query.filter_by(type_id=type_id).count() > 0:
        flash('Cannot delete room type - there are rooms assigned to it', 'error')
        return redirect(url_for('manage_room_types'))
    
    try:
        db.session.delete(room_type)
        db.session.commit()
        flash('Room type deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting room type', 'error')
    
    return redirect(url_for('manage_room_types'))

@app.route('/admin/rooms', methods=['GET', 'POST'])
@login_required
def manage_rooms():
    if request.method == 'POST':
        room = Room(
            room_number=request.form['room_number'],
            type_id=int(request.form['type_id']),
            status=request.form.get('status', 'Available')
        )
        db.session.add(room)
        db.session.commit()
        flash('Room added successfully!', 'success')
        return redirect(url_for('manage_rooms'))
    
    rooms = Room.query.all()
    room_types = RoomType.query.all()
    return render_template('admin/rooms.html', rooms=rooms, room_types=room_types)

@app.route('/admin/rooms/delete/<int:room_id>', methods=['POST'])
@login_required
def delete_room(room_id):
    room = Room.query.get_or_404(room_id)
    
    # Check if the room has any bookings
    if Booking.query.filter_by(room_id=room_id).count() > 0:
        flash('Cannot delete room - it has associated bookings', 'error')
        return redirect(url_for('manage_rooms'))
    
    try:
        db.session.delete(room)
        db.session.commit()
        flash('Room deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting room', 'error')
    
    return redirect(url_for('manage_rooms'))

# --------------------------
# Booking Management
# --------------------------
@app.route('/book-room/<int:room_id>', methods=['GET', 'POST'])
def book_room(room_id):
    room = Room.query.get_or_404(room_id)
    
    # Check if room is available
    if room.status != 'Available':
        flash('This room is not currently available for booking', 'error')
        return redirect(url_for('room_details', room_type_id=room.type_id))
    
    if request.method == 'POST':
        try:
            # Validate required fields
            required_fields = {
                'first_name': 'First Name',
                'last_name': 'Last Name',
                'email': 'Email',
                'phone': 'Phone Number',
                'check_in': 'Check-in Date',
                'check_out': 'Check-out Date'
            }
            
            missing_fields = []
            form_data = {}
            
            for field, field_name in required_fields.items():
                value = request.form.get(field, '').strip()
                if not value:
                    missing_fields.append(field_name)
                form_data[field] = value
            
            if missing_fields:
                flash(f'Missing required fields: {", ".join(missing_fields)}', 'error')
                return redirect(url_for('book_room', room_id=room.id))
            
            # Validate email format
            if not re.match(r"[^@]+@[^@]+\.[^@]+", form_data['email']):
                flash('Please enter a valid email address', 'error')
                return redirect(url_for('book_room', room_id=room.id))
            
            # Parse and validate dates
            try:
                check_in = datetime.strptime(form_data['check_in'], '%Y-%m-%d')
                check_out = datetime.strptime(form_data['check_out'], '%Y-%m-%d')
                
                if check_in < datetime.now().date():
                    flash('Check-in date cannot be in the past', 'error')
                    return redirect(url_for('book_room', room_id=room.id))
                
                if check_out <= check_in:
                    flash('Check-out date must be after check-in date', 'error')
                    return redirect(url_for('book_room', room_id=room.id))
                
                # Check if room is available for selected dates
                conflicting_bookings = Booking.query.filter(
                    Booking.room_id == room.id,
                    Booking.status.in_(['Confirmed', 'Pending']),
                    Booking.check_in < check_out,
                    Booking.check_out > check_in
                ).count()
                
                if conflicting_bookings > 0:
                    flash('This room is not available for the selected dates', 'error')
                    return redirect(url_for('book_room', room_id=room.id))
                
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD format.', 'error')
                return redirect(url_for('book_room', room_id=room.id))
            
            # Calculate duration and price
            duration = (check_out - check_in).days
            total_price = room.room_type.base_price * duration
            
            # Validate number of guests against room capacity
            adults = int(request.form.get('adults', 1))
            children = int(request.form.get('children', 0))
            
            if adults + children > room.room_type.capacity:
                flash(f'This room can only accommodate {room.room_type.capacity} guests', 'error')
                return redirect(url_for('book_room', room_id=room.id))
            
            # Handle customer (existing or new)
            customer = Customer.query.filter_by(email=form_data['email']).first()
            if not customer:
                customer = Customer(
                    first_name=form_data['first_name'],
                    last_name=form_data['last_name'],
                    email=form_data['email'],
                    phone=form_data['phone'],
                    address=request.form.get('address', ''),
                    id_number=request.form.get('id_number', '')
                )
                db.session.add(customer)
                db.session.flush()  # Ensure we have customer.id for the booking
            
            # Create booking
            booking = Booking(
                customer_id=customer.id,
                room_id=room.id,
                check_in=check_in,
                check_out=check_out,
                adults=adults,
                children=children,
                status='Pending',
                total_price=total_price,
                payment_status='Pending'
            )
            db.session.add(booking)
            
            # Update room status
            room.status = 'Reserved'
            
            db.session.commit()
            
            flash('Booking created successfully! Please complete payment', 'success')
            return redirect(url_for('initiate_payment', booking_id=booking.id))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Booking error: {str(e)}', exc_info=True)
            flash('An error occurred while processing your booking. Please try again.', 'error')
            return redirect(url_for('book_room', room_id=room.id))
    
    # For GET requests
    default_check_in = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    default_check_out = (datetime.now() + timedelta(days=2)).strftime('%Y-%m-%d')
    
    default_check_in = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    return render_template('book_room.html', 
                     room=room,
                     min_date=default_check_in)

# Add this route for checking availability
@app.route('/check-availability', methods=['POST'])
def check_availability():
    check_in = datetime.strptime(request.form['check_in'], '%Y-%m-%d')
    check_out = datetime.strptime(request.form['check_out'], '%Y-%m-%d')
    room_type_id = request.form.get('room_type_id')
    
    # Find available rooms
    available_rooms = Room.query.filter(
        Room.type_id == room_type_id,
        Room.status == 'Available',
        ~Room.bookings.any(  # Rooms not already booked for these dates
            db.and_(
                Booking.check_in < check_out,
                Booking.check_out > check_in,
                Booking.status.in_(['Confirmed', 'Pending'])
            )
        )
    ).all()
    
    return render_template('available_rooms.html', 
                         rooms=available_rooms,
                         check_in=check_in,
                         check_out=check_out)


@app.route('/admin/bookings', methods=['GET', 'POST'])
@login_required
def manage_bookings():
    if request.method == 'POST':
        try:
            # Validate required fields
            required_fields = ['customer_id', 'room_id', 'check_in', 'check_out']
            for field in required_fields:
                if field not in request.form or not request.form[field].strip():
                    flash(f'Missing required field: {field.replace("_", " ").title()}', 'error')
                    return redirect(url_for('manage_bookings'))

            # Get form data
            customer_id = int(request.form['customer_id'])
            room_id = int(request.form['room_id'])
            check_in = datetime.strptime(request.form['check_in'], '%Y-%m-%d')
            check_out = datetime.strptime(request.form['check_out'], '%Y-%m-%d')

            # Get room and calculate price
            room = Room.query.get_or_404(room_id)
            duration = (check_out - check_in).days
            if duration <= 0:
                flash('Check-out date must be after check-in date', 'error')
                return redirect(url_for('manage_bookings'))

            total_price = room.room_type.base_price * duration

            # Create booking
            booking = Booking(
                customer_id=customer_id,
                room_id=room_id,
                check_in=check_in,
                check_out=check_out,
                adults=int(request.form.get('adults', 1)),
                children=int(request.form.get('children', 0)),
                status=request.form.get('status', 'Pending'),
                total_price=total_price  # Use calculated price
            )
            
            db.session.add(booking)
            
            # Update room status if booking is confirmed
            if booking.status == 'Confirmed':
                room.status = 'Occupied'
                db.session.add(room)

            db.session.commit()
            flash('Booking created successfully!', 'success')

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating booking: {str(e)}', 'error')

        return redirect(url_for('manage_bookings'))

    # GET request handling
    bookings = Booking.query.options(
        db.joinedload(Booking.customer),
        db.joinedload(Booking.room)
    ).order_by(Booking.check_in.desc()).all()

    customers = Customer.query.all()
    rooms = Room.query.all()

    return render_template('admin/bookings.html',
                         bookings=bookings,
                         customers=customers,
                         rooms=rooms)

# --------------------------
# Staff Management
# --------------------------

@app.route('/admin/staff', methods=['GET', 'POST'])
@login_required
def manage_staff():
    if request.method == 'POST':
        staff = Staff(
            name=request.form['name'],
            email=request.form['email'],
            phone=request.form['phone'],
            position=request.form.get('position', 'Staff')
            # staff_id will auto-increment
        )
        db.session.add(staff)
        db.session.commit()
        flash('Staff member added successfully!', 'success')
        return redirect(url_for('manage_staff'))
    
    staff_members = Staff.query.all()
    return render_template('admin/staff.html', staff_members=staff_members)

@app.route('/admin/staff/delete/<int:staff_id>', methods=['POST'])
@login_required
def delete_staff(staff_id):
    staff = Staff.query.get_or_404(staff_id)
    db.session.delete(staff)
    db.session.commit()
    flash('Staff member deleted successfully', 'success')
    return redirect(url_for('manage_staff'))

# --------------------------
# Reports and Queries
# --------------------------

@app.route('/admin/reports')
@login_required
def view_reports():
    # Calculate monthly revenue
    revenue_data = db.session.query(
        db.func.strftime('%Y-%m', Booking.created_at),
        db.func.sum(Booking.total_price)
    ).filter(Booking.status == 'Completed').group_by(
        db.func.strftime('%Y-%m', Booking.created_at)
    ).all()
    
    return render_template('admin/reports.html',
                         revenue_data=revenue_data,
                         total_revenue=sum(r[1] for r in revenue_data))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        # Process the form data here
        flash('Your message has been sent!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html', form=form)

@app.route('/admin/queries', methods=['GET', 'POST'])
@login_required
def manage_queries():
    if request.method == 'POST':
        query = Query(
            question=request.form['question'],
            answer=request.form['answer']
        )
        db.session.add(query)
        db.session.commit()
        flash('Query added successfully!', 'success')
        return redirect(url_for('manage_queries'))
    
    queries = Query.query.all()
    return render_template('admin/queries.html', queries=queries)

# ======================
# Payment Routes
# ======================
# For customer registration payments
@app.route('/payment/customer/<int:customer_id>', methods=['GET', 'POST'])
def initiate_customer_payment(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    
    if request.method == 'POST':
        method = request.form.get('payment_method', 'telebirr')
        
        # Create payment record (initial deposit payment)
        payment = Payment(
            customer_id=customer.id,
            amount=100,  # Example: $100 registration deposit
            method=method,
            transaction_id=f"TB-CUST-{customer.id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            status='Pending'
        )
        db.session.add(payment)
        
        try:
            if method == 'telebirr':
                # Generate callback URL with payment ID
                callback_url = url_for('telebirr_callback', payment_id=payment.id, _external=True)
                
                # Generate Telebirr payment request
                payment_request = generate_telebirr_payment_request(
                    entity=customer,
                    callback_url=callback_url,
                    amount=100,  # Registration deposit amount
                    description="Registration Deposit"
                )
                
                payment.status = 'Pending'
                payment.transaction_id = payment_request.get('outTradeNo', payment.transaction_id)
                
                db.session.commit()
                
                # In production, redirect to actual Telebirr payment URL
                # For demo, show simulated payment page
                return render_template('telebirr_payment.html',
                                    payment=payment,
                                    customer=customer,
                                    payment_url="#")  # Replace with payment_request['url']
                
            elif method == 'cbe':
                # Handle CBE payment logic
                pass
                
            db.session.commit()
            return redirect(url_for('payment_status', payment_id=payment.id))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Payment initiation failed: {str(e)}')
            flash('Payment initiation failed. Please try again.', 'error')
    
    # GET request - show payment options
    return render_template('payment_options.html', customer=customer)

# For booking payments
@app.route('/payment/booking/<int:booking_id>', methods=['GET', 'POST'])
def initiate_booking_payment(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    if booking.payment_status == 'Paid':
        flash('This booking has already been paid for', 'warning')
        return redirect(url_for('booking_details', booking_id=booking.id))
    
    if request.method == 'POST':
        method = request.form.get('payment_method')
        
        # Create payment record
        payment = Payment(
            booking_id=booking.id,
            customer_id=booking.customer_id,
            amount=booking.total_price,
            method=method,
            transaction_id=f"TB-BOOK-{booking.id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            status='Pending'
        )
        db.session.add(payment)
        
        try:
            if method == 'telebirr':
                callback_url = url_for('telebirr_callback', payment_id=payment.id, _external=True)
                
                payment_request = generate_telebirr_payment_request(
                    entity=booking,
                    callback_url=callback_url,
                    amount=booking.total_price,
                    description=f"Booking #{booking.id}"
                )
                
                payment.status = 'Pending'
                payment.transaction_id = payment_request.get('outTradeNo', payment.transaction_id)
                
                db.session.commit()
                
                return render_template('telebirr_payment.html',
                                    booking=booking,
                                    payment=payment,
                                    payment_url="https://api.telebirr.com")  # Replace with payment_request['url']
                
            elif method == 'cbe':
                # Handle CBE payment logic
                pass
                
            db.session.commit()
            return redirect(url_for('payment_status', payment_id=payment.id))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Payment initiation failed: {str(e)}')
            flash('Payment initiation failed. Please try again.', 'error')
    
    return render_template('payment_options.html', booking=booking)
# ======================
# New Additional Routes
# ======================

@app.route('/admin/bookings/edit/<int:booking_id>', methods=['GET', 'POST'])
@login_required
def edit_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    if request.method == 'POST':
        booking.customer_id = int(request.form['customer_id'])
        booking.room_id = int(request.form['room_id'])
        booking.check_in = datetime.strptime(request.form['check_in'], '%Y-%m-%d')
        booking.check_out = datetime.strptime(request.form['check_out'], '%Y-%m-%d')
        booking.adults = int(request.form.get('adults', 1))
        booking.children = int(request.form.get('children', 0))
        booking.status = request.form.get('status', 'Pending')
        booking.total_price = float(request.form['total_price'])
        
        db.session.commit()
        flash('Booking updated successfully!', 'success')
        return redirect(url_for('manage_bookings'))
    
    customers = Customer.query.all()
    rooms = Room.query.all()
    return render_template('admin/edit_booking.html', 
                         booking=booking,
                         customers=customers,
                         rooms=rooms)

@app.route('/admin/bookings/delete/<int:booking_id>', methods=['POST'])
@login_required
def delete_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    db.session.delete(booking)
    db.session.commit()
    flash('Booking deleted successfully', 'success')
    return redirect(url_for('manage_bookings'))

@app.route('/admin/room-types/edit/<int:type_id>', methods=['GET', 'POST'])
@login_required
def edit_room_type(type_id):
    room_type = RoomType.query.get_or_404(type_id)
    if request.method == 'POST':
        room_type.name = request.form['name']
        room_type.description = request.form.get('description', '')
        room_type.base_price = float(request.form['base_price'])
        room_type.capacity = int(request.form['capacity'])
        room_type.image = request.form.get('image', room_type.image)
        
        db.session.commit()
        flash('Room type updated successfully!', 'success')
        return redirect(url_for('manage_room_types'))
    
    return render_template('admin/edit_room_type.html', room_type=room_type)

@app.route('/admin/rooms/edit/<int:room_id>', methods=['GET', 'POST'])
@login_required
def edit_room(room_id):
    room = Room.query.get_or_404(room_id)
    if request.method == 'POST':
        room.room_number = request.form['room_number']
        room.type_id = int(request.form['type_id'])
        room.status = request.form.get('status', 'Available')
        
        db.session.commit()
        flash('Room updated successfully!', 'success')
        return redirect(url_for('manage_rooms'))
    
    room_types = RoomType.query.all()
    return render_template('admin/edit_room.html', 
                         room=room,
                         room_types=room_types)

@app.route('/admin/staff/edit/<int:staff_id>', methods=['GET', 'POST'])
@login_required
def edit_staff(staff_id):
    staff = Staff.query.get_or_404(staff_id)
    if request.method == 'POST':
        staff.name = request.form['name']
        staff.email = request.form['email']
        staff.phone = request.form['phone']
        staff.position = request.form.get('position', 'Staff')
        
        db.session.commit()
        flash('Staff member updated successfully!', 'success')
        return redirect(url_for('manage_staff'))
    
    return render_template('admin/edit_staff.html', staff=staff)

@app.route('/admin/queries/resolve/<int:query_id>', methods=['POST'])
@login_required
def resolve_query(query_id):
    query = Query.query.get_or_404(query_id)
    query.answer = request.form.get('answer', '')
    query.resolved = True
    db.session.commit()
    flash('Query resolved successfully', 'success')
    return redirect(url_for('manage_queries'))

@app.route('/admin/queries/delete/<int:query_id>', methods=['POST'])
@login_required
def delete_query(query_id):
    query = Query.query.get_or_404(query_id)
    db.session.delete(query)
    db.session.commit()
    flash('Query deleted successfully', 'success')
    return redirect(url_for('manage_queries'))

@app.route('/api/rooms/available', methods=['GET'])
def api_available_rooms():
    check_in = request.args.get('check_in')
    check_out = request.args.get('check_out')
    
    if not check_in or not check_out:
        return jsonify({'error': 'Missing check_in or check_out parameters'}), 400
    
    try:
        check_in = datetime.strptime(check_in, '%Y-%m-%d')
        check_out = datetime.strptime(check_out, '%Y-%m-%d')
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
    
    # Find available rooms
    available_rooms = Room.query.filter(
        Room.status == 'Available',
        ~Room.bookings.any(
            db.and_(
                Booking.check_in < check_out,
                Booking.check_out > check_in,
                Booking.status.in_(['Confirmed', 'Pending'])
            )
        )
    ).all()
    
    result = [{
        'id': room.id,
        'room_number': room.room_number,
        'type': room.room_type.name,
        'price': room.room_type.base_price,
        'capacity': room.room_type.capacity
    } for room in available_rooms]
    
    return jsonify(result)
@app.route('/api/room/<int:room_id>/price')
def room_price(room_id):
    room = Room.query.get_or_404(room_id)
    check_in = request.args.get('check_in')
    check_out = request.args.get('check_out')

    try:
        check_in_date = datetime.fromisoformat(check_in)
        check_out_date = datetime.fromisoformat(check_out)
        duration = (check_out_date - check_in_date).days
        if duration <= 0:
            return jsonify({'error': 'Invalid date range'}), 400
            
        total_price = room.room_type.base_price * duration
        return jsonify({
            'total_price': total_price,
            'currency': 'USD',
            'nights': duration
        })
        
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Validate required fields
            required_fields = ['first_name', 'last_name', 'email', 'phone', 'password']
            missing_fields = [field for field in required_fields if not request.form.get(field)]
            
            if missing_fields:
                flash(f'Missing required fields: {", ".join(missing_fields)}', 'error')
                return redirect(url_for('register'))
            
            # Check if email exists
            if Customer.query.filter_by(email=request.form['email']).first():
                flash('Email already registered', 'error')
                return redirect(url_for('register'))
            
            # Create customer
            customer = Customer(
                first_name=request.form['first_name'],
                last_name=request.form['last_name'],
                email=request.form['email'],
                phone=request.form['phone'],
                address=request.form.get('address', ''),
                id_number=request.form.get('id_number', '')
            )
            db.session.add(customer)
            db.session.flush()  # Get the customer ID without committing
            
            # Create a payment record
            payment = Payment(
                customer_id=customer.id,
                amount=100,  # Registration fee amount
                method='telebirr',
                transaction_id=f"TB-REG-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                status='Pending'
            )
            db.session.add(payment)
            db.session.commit()
            
            # Store in session for payment completion
            session['pending_payment'] = {
                'payment_id': payment.id,
                'customer_id': customer.id,
                'amount': 100
            }
            
            # Redirect to Telebirr payment page
            return redirect(url_for('telebirr_payment', payment_id=payment.id))
            
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            app.logger.error(f'Registration error: {str(e)}')
    
    return render_template('register.html')

@app.route('/payment/telebirr/<int:payment_id>', methods=['GET', 'POST'])
def telebirr_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    customer = Customer.query.get_or_404(payment.customer_id)
    
    try:
        callback_url = url_for('telebirr_callback', payment_id=payment.id, _external=True)
        payment_request = TelebirrPayment.generate_payment_request(
            amount=payment.amount,
            out_trade_no=payment.transaction_id,
            notify_url=callback_url
        )
        
        response = requests.post(
            payment_request['url'],
            headers=payment_request['headers'],
            json=payment_request['data'],
            timeout=30
        )
        
        payment_response = response.json()
        if response.status_code == 200 and payment_response.get('code') == '200':
            payment.status = 'Processing'
            payment.transaction_id = payment_response.get('outTradeNo', payment.transaction_id)
            db.session.commit()
            
            # Log successful payment initiation
            app.logger.info(f"Payment initiated - ID: {payment.id}, Amount: {payment.amount}, Ref: {payment.transaction_id}")
            
            return redirect(payment_response['data']['paymentUrl'])
        
        # Log failed payment initiation
        app.logger.error(f"Payment initiation failed - ID: {payment.id}, Status: {response.status_code}, Response: {payment_response}")
        flash('Payment initiation failed', 'error')
        
    except Exception as e:
        app.logger.error(f"Payment processing error - ID: {payment.id}, Error: {str(e)}", exc_info=True)
        flash('Payment processing error', 'error')
    
    return render_template('payment_error.html')

@app.route('/payment/telebirr/callback/<int:payment_id>', methods=['POST'])
def telebirr_callback(payment_id):
    """Secure Telebirr payment callback handler"""
    payment = Payment.query.get_or_404(payment_id)
    callback_data = request.get_json()
    
    try:
        # Verify signature
        sign = callback_data.get('sign')
        params = {k: v for k, v in callback_data.items() if k != 'sign'}
        
        if not TelebirrPayment.verify_callback_signature(params, sign):
            app.logger.warning(f"Invalid signature for payment {payment_id}")
            raise ValueError("Invalid signature")
        
        if callback_data.get('tradeStatus') == 'SUCCESS':
            # Update payment status
            payment.status = 'Paid'
            payment.transaction_id = callback_data.get('tradeNo')
            
            # Update booking status if this is a booking payment
            if payment.booking_id:
                booking = Booking.query.get(payment.booking_id)
                if booking:
                    booking.payment_status = 'Paid'
                    booking.status = 'Confirmed'
            
            db.session.commit()
            
            # Clear session
            if 'pending_payment' in session:
                session.pop('pending_payment')
            
            # Log successful payment
            app.logger.info(f"Payment successful - ID: {payment.id}, Ref: {payment.transaction_id}")
            
            return jsonify({'status': 'success'})
        
        # Payment failed
        payment.status = 'Failed'
        db.session.commit()
        
        # Log failed payment
        app.logger.warning(f"Payment failed - ID: {payment.id}, Status: {callback_data.get('tradeStatus')}")
        
        return jsonify({'status': 'failed'}), 400
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Callback error - ID: {payment_id}, Error: {str(e)}', exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500


# Add a new route for payment status check
@app.route('/payment/status/<int:payment_id>')
def payment_status(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    
    # Add client-side polling for payment status
    return render_template('payment_status.html', 
                         payment=payment,
                         poll_interval=5000)

@app.route('/payment/receipt/<int:payment_id>')
def download_receipt(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    receipt = payment.generate_receipt()
    
    filename = f"receipt_{payment.receipt_number}.pdf"
    return Response(
        receipt,
        mimetype="application/pdf",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

# Then later in your file (after all routes)
if __name__ == '__main__':
    # Validate configuration first
    validate_config()
    
    # Initialize database
    initialize_database()
    
    # Run the application
    app.run(debug=True)