import hashlib
import hmac
import base64
import json
import time

def generate_jwt(payload, secret_key, algorithm='HS256', expiry_seconds=3600):
    header = {'alg': algorithm, 'typ': 'JWT'}
    header_json = json.dumps(header)
    header_base64 = base64.urlsafe_b64encode(header_json.encode('utf-8')).decode('utf-8').rstrip('=')

    payload['exp'] = int(time.time()) + expiry_seconds
    payload_json = json.dumps(payload)
    payload_base64 = base64.urlsafe_b64encode(payload_json.encode('utf-8')).decode('utf-8').rstrip('=')

    unsigned_token = f"{header_base64}.{payload_base64}"
    message = unsigned_token.encode('utf-8')
    key = secret_key.encode('utf-8')
    signature = hmac.new(key, message, hashlib.sha256).digest()
    signature_base64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

    return f"{unsigned_token}.{signature_base64}"

def verify_jwt(token, secret_key, algorithms=['HS256']):
    try:
        header_base64, payload_base64, signature_base64 = token.split('.')
    except ValueError:
        return False, "Invalid token format"

    try:
        header_json = base64.urlsafe_b64decode(header_base64 + '===').decode('utf-8')
        header = json.loads(header_json)
    except (base64.binascii.Error, json.JSONDecodeError):
        return False, "Invalid header encoding"

    if header.get('alg') not in algorithms:
        return False, "Algorithm not supported"

    try:
        payload_json = base64.urlsafe_b64decode(payload_base64 + '===').decode('utf-8')
        payload = json.loads(payload_json)
    except (base64.binascii.Error, json.JSONDecodeError):
        return False, "Invalid payload encoding"

    if 'exp' in payload and payload['exp'] < time.time():
        return False, "Token has expired"

    unsigned_token = f"{header_base64}.{payload_base64}"
    message = unsigned_token.encode('utf-8')
    key = secret_key.encode('utf-8')
    expected_signature = hmac.new(key, message, hashlib.sha256).digest()
    expected_signature_base64 = base64.urlsafe_b64encode(expected_signature).decode('utf-8').rstrip('=')

    if hmac.compare_digest(signature_base64, expected_signature_base64):
        return True, payload
    else:
        return False, "Invalid signature"
