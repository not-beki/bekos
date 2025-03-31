import requests
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from datetime import datetime
from flask import current_app

def encrypt_telebirr_data(data):
    """Encrypt data using Telebirr's public key"""
    public_key = current_app.config['TELEBIRR_PUBLIC_KEY']
    rsa_key = RSA.importKey(public_key)
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted = cipher.encrypt(json.dumps(data).encode())
    return base64.b64encode(encrypted).decode()

def generate_telebirr_payment_request(booking, callback_url):
    """Generate payment request for Telebirr"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    nonce = timestamp  # Simple nonce using timestamp
    
    request_data = {
        "outTradeNo": f"TB-{booking.id}-{timestamp}",
        "subject": f"Hotel Booking #{booking.id}",
        "totalAmount": str(booking.total_price),
        "shortCode": current_app.config['TELEBIRR_SHORT_CODE'],
        "notifyUrl": callback_url,
        "returnUrl": callback_url,
        "timeoutExpress": "30",  # 30 minutes
        "nonce": nonce,
        "timestamp": timestamp
    }
    
    encrypted_data = encrypt_telebirr_data(request_data)
    
    headers = {
        "appkey": current_app.config['TELEBIRR_APP_KEY'],
        "sign": current_app.config['TELEBIRR_APP_SECRET'],  # In production, you should hash this
        "content-type": "application/json"
    }
    
    payload = {
        "data": encrypted_data
    }
    
    return {
        "url": f"{current_app.config['TELEBIRR_API_BASE_URL']}/payment/create",
        "headers": headers,
        "data": payload
    }

def verify_telebirr_payment(transaction_id):
    """Verify a payment with Telebirr"""
    headers = {
        "appkey": current_app.config['TELEBIRR_APP_KEY'],
        "sign": current_app.config['TELEBIRR_APP_SECRET'],
        "content-type": "application/json"
    }
    
    response = requests.get(
        f"{current_app.config['TELEBIRR_API_BASE_URL']}/payment/query/{transaction_id}",
        headers=headers
    )
    
    if response.status_code == 200:
        return response.json()
    return None