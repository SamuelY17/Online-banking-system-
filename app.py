import os
import sqlite3
import hashlib
import secrets
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import re

# Create Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Enable CORS for all routes
CORS(app, supports_credentials=True)

# Password hashing utility
class PasswordHasher:
    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_hex(32)
        pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}:{pwd_hash}"

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        try:
            salt, pwd_hash = stored_hash.split(':')
            new_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return new_hash == pwd_hash
        except:
            return False

# Database initialization
def init_database():
    conn = sqlite3.connect('web_banking.db')
    cursor = conn.cursor()

    cursor.execute(""" 
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            account_id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_number TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            account_type TEXT NOT NULL,
            balance DECIMAL(15,2) DEFAULT 0.00,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER,
            transaction_type TEXT NOT NULL,
            amount DECIMAL(15,2) NOT NULL,
            balance_after DECIMAL(15,2) NOT NULL,
            description TEXT,
            recipient_account TEXT,
            transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts (account_id)
        )
    """)

    conn.commit()
    conn.close()

# JWT Token utilities
def create_token(user_id: int) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

def verify_token(token: str):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload.get('user_id')
    except:
        return None

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        if token.startswith('Bearer '):
            token = token[7:]

        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Token is invalid'}), 401

        return f(user_id, *args, **kwargs)
    return decorated

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()

        required_fields = ['username', 'email', 'password', 'full_name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400

        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, data['email']):
            return jsonify({'error': 'Invalid email format'}), 400

        if len(data['password']) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        password_hash = PasswordHasher.hash_password(data['password'])

        conn = sqlite3.connect('web_banking.db')
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, full_name, phone)
                VALUES (?, ?, ?, ?, ?)
            """, (data['username'], data['email'], password_hash, 
                  data['full_name'], data.get('phone')))

            user_id = cursor.lastrowid
            conn.commit()

            account_number = ''.join([str(secrets.randbelow(10)) for _ in range(10)])
            cursor.execute("""
                INSERT INTO accounts (account_number, user_id, account_type, balance)
                VALUES (?, ?, ?, ?)
            """, (account_number, user_id, 'savings', 0.00))

            conn.commit()
            conn.close()

            return jsonify({
                'message': 'Registration successful',
                'user_id': user_id
            }), 201

        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Username or email already exists'}), 409

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        conn = sqlite3.connect('web_banking.db')
        cursor = conn.cursor()

        cursor.execute("""
            SELECT user_id, username, password_hash, full_name, email
            FROM users WHERE username = ? AND is_active = 1
        """, (username,))

        user = cursor.fetchone()
        conn.close()

        if not user or not PasswordHasher.verify_password(password, user[2]):
            return jsonify({'error': 'Invalid credentials'}), 401

        token = create_token(user[0])

        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'user_id': user[0],
                'username': user[1],
                'full_name': user[3],
                'email': user[4]
            }
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/accounts', methods=['GET'])
@token_required
def get_accounts(user_id):
    try:
        conn = sqlite3.connect('web_banking.db')
        cursor = conn.cursor()

        cursor.execute("""
            SELECT account_id, account_number, account_type, balance, created_at
            FROM accounts WHERE user_id = ? AND is_active = 1
        """, (user_id,))

        accounts = []
        for row in cursor.fetchall():
            accounts.append({
                'account_id': row[0],
                'account_number': row[1],
                'account_type': row[2],
                'balance': float(row[3]),
                'created_at': row[4]
            })

        conn.close()
        return jsonify({'accounts': accounts}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/transactions', methods=['POST'])
@token_required
def create_transaction(user_id):
    try:
        data = request.get_json()

        transaction_type = data.get('type')
        amount = float(data.get('amount', 0))
        account_number = data.get('account_number')
        description = data.get('description', '')

        if transaction_type not in ['deposit', 'withdrawal']:
            return jsonify({'error': 'Invalid transaction type'}), 400

        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400

        conn = sqlite3.connect('web_banking.db')
        cursor = conn.cursor()

        cursor.execute("""
            SELECT account_id, balance FROM accounts 
            WHERE account_number = ? AND user_id = ? AND is_active = 1
        """, (account_number, user_id))

        account = cursor.fetchone()
        if not account:
            conn.close()
            return jsonify({'error': 'Account not found'}), 404

        account_id, current_balance = account

        if transaction_type == 'deposit':
            new_balance = current_balance + amount
        else:
            if current_balance < amount:
                conn.close()
                return jsonify({'error': 'Insufficient funds'}), 400
            new_balance = current_balance - amount

        cursor.execute("""
            UPDATE accounts SET balance = ? WHERE account_id = ?
        """, (new_balance, account_id))

        cursor.execute("""
            INSERT INTO transactions (account_id, transaction_type, amount, balance_after, description)
            VALUES (?, ?, ?, ?, ?)
        """, (account_id, transaction_type, amount, new_balance, description))

        conn.commit()
        conn.close()

        return jsonify({
            'message': f'{transaction_type.title()} successful',
            'new_balance': new_balance
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/transactions/<account_number>', methods=['GET'])
@token_required
def get_transactions(user_id, account_number):
    try:
        conn = sqlite3.connect('web_banking.db')
        cursor = conn.cursor()

        cursor.execute("""
            SELECT account_id FROM accounts 
            WHERE account_number = ? AND user_id = ?
        """, (account_number, user_id))

        account = cursor.fetchone()
        if not account:
            conn.close()
            return jsonify({'error': 'Account not found'}), 404

        cursor.execute("""
            SELECT transaction_type, amount, balance_after, description, transaction_date
            FROM transactions 
            WHERE account_id = ? 
            ORDER BY transaction_date DESC 
            LIMIT 50
        """, (account[0],))

        transactions = []
        for row in cursor.fetchall():
            transactions.append({
                'type': row[0],
                'amount': float(row[1]),
                'balance_after': float(row[2]),
                'description': row[3],
                'date': row[4]
            })

        conn.close()
        return jsonify({'transactions': transactions}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Initialize database
init_database()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
