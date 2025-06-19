from flask import Flask, request, jsonify, send_file
import pymysql
import bcrypt
from functools import wraps
import io
import base64
from flask_cors import CORS
import smtplib
from email.mime.text import MIMEText
import os
import secrets
import string

app = Flask(__name__)

CORS(app)

# Database connection configuration
def get_db_connection():
    return pymysql.connect(
        host='sims21.mysql.pythonanywhere-services.com',
        user='sims21',
        password='sorted@123',
        database='sims21$default',
        cursorclass=pymysql.cursors.DictCursor
    )

# Role-based access decorator
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = request.headers.get('User-ID')
            if not user_id:
                return jsonify({'message': 'User-ID required'}), 401
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT role FROM users WHERE user_id = %s AND is_active = TRUE", (user_id,))
                    user = cursor.fetchone()
                    if not user or user['role'] not in roles:
                        return jsonify({'message': 'Unauthorized'}), 403
                    kwargs['current_user_role'] = user['role']
                    kwargs['current_user_id'] = user_id
            finally:
                conn.close()
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Function to generate a random 12-character password
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

# Function to send email with the temporary password
def send_password_email(email, username, password):
    smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_user = os.getenv('SMTP_USER', 'waynejunj@gmail.com')
    smtp_password = os.getenv('SMTP_PASSWORD', 'jsml ywkw tizi mlex')

    msg = MIMEText(
        f"Dear {username},\n\n"
        f"Your account has been created successfully. Your temporary password is: {password}\n\n"
        f"Please log in at http://sims21.pythonanywhere.com/login and change your password in your profile.\n\n"
        f"Best regards,\nSIMS Team"
    )
    msg['Subject'] = 'Your Temporary Password'
    msg['From'] = smtp_user
    msg['To'] = email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        return True
    except Exception as e:
        app.logger.error(f"Failed to send email: {str(e)}")
        return False

# =========== USER ROUTES ==========
@app.route('/register', methods=['POST'])
# @role_required(['admin'])
def register_user():
    data = request.form
    username = data.get('username')
    email = data.get('email')
    role = data.get('role', 'staff')
    full_name = data.get('full_name')

    if not username or not email or role not in ['admin', 'staff']:
        return jsonify({'message': 'Invalid input'}), 400

    # Generate random password
    password = generate_random_password()
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, full_name, email) VALUES (%s, %s, %s, %s, %s)",
                (username, password_hash, role, full_name, email)
            )
        conn.commit()

        # Send email with temporary password
        if not send_password_email(email, username, password):
            return jsonify({'message': 'User registered but failed to send email'}), 201

        return jsonify({'message': 'User registered successfully and password sent to email'}), 201
    except pymysql.IntegrityError:
        return jsonify({'message': 'Username or email already exists'}), 400
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.form
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s AND is_active = TRUE", (username,))
            user = cursor.fetchone()
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                avatar = base64.b64encode(user['avatar']).decode('utf-8') if user['avatar'] else None
                return jsonify({
                    'user_id': user['user_id'],
                    'username': user['username'],
                    'role': user['role'],
                    'full_name': user['full_name'],
                    'email': user['email'],
                    'avatar': avatar,
                    'avatar_mimetype': user['avatar_mimetype'],
                    'message': 'Login successful'
                })
            return jsonify({'message': 'Invalid credentials'}), 401
    finally:
        conn.close()

@app.route('/api/users', methods=['GET'])
@role_required(['admin'])
def get_all_users(current_user_id, current_user_role):
    try:
        connection = get_db_connection()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT user_id, username, email, full_name, role, created_at
                    FROM users
                """)
                users = cursor.fetchall()
        return jsonify(users)
    except Exception as e:
        app.logger.error(f"Error in get_all_users: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['GET'])
@role_required(['admin'])
def get_user(user_id, current_user_id, current_user_role):
    try:
        connection = get_db_connection()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT user_id, username, email, full_name, role, is_active, created_at
                    FROM users WHERE user_id = %s
                """, (user_id,))
                user = cursor.fetchone()
                if not user:
                    return jsonify({"error": "User not found"}), 404
                if user['created_at']:
                    user['created_at'] = user['created_at'].isoformat()
        return jsonify(user)
    except Exception as e:
        app.logger.error(f"Error in get_user: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@role_required(['admin'])
def update_user(user_id, current_user_id, current_user_role):
    try:
        data = request.form
        connection = get_db_connection()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
                if not cursor.fetchone():
                    return jsonify({"error": "User not found"}), 404

                sql = """
                    UPDATE users SET
                        username = %s,
                        email = %s,
                        full_name = %s,
                        role = %s,
                        is_active = %s
                    WHERE user_id = %s
                """
                cursor.execute(sql, (
                    data.get('username'),
                    data.get('email'),
                    data.get('full_name'),
                    data.get('role', 'staff'),
                    bool(data.get('is_active', False)),
                    user_id
                ))
            connection.commit()
        app.logger.info(f"User {user_id} updated successfully")
        return jsonify({"message": "User updated successfully"})
    except Exception as e:
        app.logger.error(f"Error in update_user: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@role_required(['admin'])
def delete_user(user_id, current_user_id, current_user_role):
    try:
        connection = get_db_connection()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
                if not cursor.fetchone():
                    return jsonify({"error": "User not found"}), 404

                cursor.execute("UPDATE users SET is_active = FALSE WHERE user_id = %s", (user_id,))
            connection.commit()
        app.logger.info(f"User {user_id} deleted successfully")
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        app.logger.error(f"Error in delete_user: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/users/<int:user_id>/status', methods=['PUT'])
@role_required(['admin'])
def update_user_status(user_id):
    data = request.json
    is_active = data.get('is_active')

    if is_active is None:
        return jsonify({'message': 'is_active field is required'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET is_active = %s WHERE user_id = %s",
                (is_active, user_id)
            )
            if cursor.rowcount == 0:
                return jsonify({'message': 'User not found'}), 404
        conn.commit()
        return jsonify({'message': 'User status updated successfully'})
    finally:
        conn.close()

@app.route('/profile/<int:user_id>', methods=['GET'])
@role_required(['admin', 'staff'])
def get_profile(user_id, current_user_id, current_user_role):
    if current_user_role != 'admin' and str(current_user_id) != str(user_id):
        return jsonify({'message': 'Unauthorized to view this profile'}), 403

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT user_id, username, role, full_name, email, avatar, avatar_mimetype FROM users WHERE user_id = %s AND is_active = TRUE", (user_id,))
            user = cursor.fetchone()
            if not user:
                return jsonify({'message': 'User not found'}), 404
            user['avatar'] = base64.b64encode(user['avatar']).decode('utf-8') if user['avatar'] else None
            return jsonify(user)
    finally:
        conn.close()

@app.route('/profile/<int:user_id>', methods=['PUT'])
@role_required(['admin', 'staff'])
def update_profile(user_id, current_user_id, current_user_role):
    if current_user_role != 'admin' and str(current_user_id) != str(user_id):
        return jsonify({'message': 'Unauthorized to update this profile'}), 403

    data = request.form
    full_name = data.get('full_name')
    email = data.get('email')
    avatar_file = request.files.get('avatar')

    avatar = None
    avatar_mimetype = None
    if avatar_file:
        avatar = avatar_file.read()
        avatar_mimetype = avatar_file.mimetype
        if avatar_mimetype not in ['image/png', 'image/jpeg']:
            return jsonify({'message': 'Invalid image format. Use PNG or JPEG.'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            update_fields = []
            values = []
            if full_name:
                update_fields.append("full_name = %s")
                values.append(full_name)
            if email:
                update_fields.append("email = %s")
                values.append(email)
            if avatar:
                update_fields.append("avatar = %s")
                values.append(avatar)
                update_fields.append("avatar_mimetype = %s")
                values.append(avatar_mimetype)

            if not update_fields:
                return jsonify({'message': 'No fields to update'}), 400

            values.append(user_id)
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE user_id = %s"
            cursor.execute(query, values)
            if cursor.rowcount == 0:
                return jsonify({'message': 'User not found'}), 404
        conn.commit()
        return jsonify({'message': 'Profile updated successfully'})
    except pymysql.IntegrityError:
        return jsonify({'message': 'Email already exists'}), 400
    finally:
        conn.close()

@app.route('/profile/<int:user_id>/password', methods=['PUT'])
@role_required(['admin', 'staff'])
def update_password(user_id, current_user_id, current_user_role):
    if current_user_role != 'admin' and str(current_user_id) != str(user_id):
        return jsonify({'message': 'Unauthorized to update this password'}), 403

    data = request.form
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if not current_password or not new_password or not confirm_password:
        return jsonify({'message': 'All password fields are required'}), 400

    if new_password != confirm_password:
        return jsonify({'message': 'New passwords do not match'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT password_hash FROM users WHERE user_id = %s", (user_id,))
            user = cursor.fetchone()
            if not user or not bcrypt.checkpw(current_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                return jsonify({'message': 'Current password is incorrect'}), 401

            new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute(
                "UPDATE users SET password_hash = %s WHERE user_id = %s",
                (new_password_hash, user_id))
            conn.commit()
            return jsonify({'message': 'Password updated successfully'})
    finally:
        conn.close()

# ========== INSTRUMENTS ROUTE =========
@app.route('/instruments', methods=['POST'])
@role_required(['admin'])
def add_instrument():
    data = request.form
    name = data.get('name')
    serial_number = data.get('serial_number')
    barcode = data.get('barcode')
    type = data.get('type')
    description = data.get('description')

    if not name or not serial_number or not barcode:
        return jsonify({'message': 'Missing required fields'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO instruments (name, serial_number, barcode, type, description) VALUES (%s, %s, %s, %s, %s)",
                (name, serial_number, barcode, type, description)
            )
        conn.commit()
        return jsonify({'message': 'Instrument added successfully'}), 201
    except pymysql.IntegrityError:
        return jsonify({'message': 'Serial number or barcode already exists'}), 400
    finally:
        conn.close()

@app.route('/instruments', methods=['GET'])
@role_required(['admin', 'staff'])
def get_instruments():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM instruments")
            instruments = cursor.fetchall()
        return jsonify(instruments)
    finally:
        conn.close()

@app.route('/instruments/<int:instrument_id>', methods=['PUT'])
@role_required(['admin'])
def update_instrument(instrument_id):
    data = request.form
    name = data.get('name')
    type = data.get('type')
    description = data.get('description')

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE instruments SET name = %s, type = %s, description = %s WHERE instrument_id = %s",
                (name, type, description, instrument_id)
            )
            if cursor.rowcount == 0:
                return jsonify({'message': 'Instrument not found'}), 404
        conn.commit()
        return jsonify({'message': 'Instrument updated successfully'})
    finally:
        conn.close()

@app.route('/instruments/<int:instrument_id>', methods=['DELETE'])
@role_required(['admin'])
def delete_instrument(instrument_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM instruments WHERE instrument_id = %s", (instrument_id,))
            if cursor.rowcount == 0:
                return jsonify({'message': 'Instrument not found'}), 404
        conn.commit()
        return jsonify({'message': 'Instrument deleted successfully'})
    finally:
        conn.close()

# =========== INSTRUMENT SET ROUTES ==========
@app.route('/sets', methods=['POST'])
@role_required(['admin'])
def add_set():
    data = request.form
    name = data.get('name')
    barcode = data.get('barcode')
    total_items = data.get('total_items')
    items = request.form.getlist('items[]')

    if not name or not barcode or not total_items or not items:
        return jsonify({'message': 'Missing required fields'}), 400

    try:
        items = [eval(item) for item in items]
    except:
        return jsonify({'message': 'Invalid items format'}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO instrument_sets (name, barcode, total_items) VALUES (%s, %s, %s)",
                (name, barcode, total_items)
            )
            set_id = cursor.lastrowid
            for item in items:
                cursor.execute(
                    "INSERT INTO set_items (set_id, instrument_id, expected_count, actual_count) VALUES (%s, %s, %s, %s)",
                    (set_id, item['instrument_id'], item['expected_count'], item['actual_count'])
                )
        conn.commit()
        return jsonify({'message': 'Set added successfully', 'set_id': set_id}), 201
    except pymysql.IntegrityError:
        return jsonify({'message': 'Barcode already exists'}), 400
    finally:
        conn.close()

@app.route('/sets', methods=['GET'])
@role_required(['admin', 'staff'])
def get_sets():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM instrument_sets")
            sets = cursor.fetchall()
            for s in sets:
                cursor.execute("SELECT * FROM set_items WHERE set_id = %s", (s['set_id'],))
                s['items'] = cursor.fetchall()
        return jsonify(sets)
    finally:
        conn.close()

@app.route('/sets/<int:set_id>', methods=['PUT'])
@role_required(['admin'])
def update_set(set_id):
    data = request.form
    status = data.get('status')
    condition_status = data.get('condition_status')
    condition_remark = data.get('condition_remark')
    location = data.get('location')

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE instrument_sets SET status = %s, condition_status = %s, condition_remark = %s, location = %s WHERE set_id = %s",
                (status, condition_status, condition_remark, location, set_id)
            )
            if cursor.rowcount == 0:
                return jsonify({'message': 'Set not found'}), 404
        conn.commit()
        return jsonify({'message': 'Set updated successfully'})
    finally:
        conn.close()

# ========== BARCODE SCANNING ROUTE =========
@app.route('/scan', methods=['POST'])
@role_required(['admin', 'staff'])
def scan_barcode():
    data = request.form
    barcode = data.get('barcode')
    user_id = request.headers.get('User-ID')
    action = data.get('action', 'scan')
    location = data.get('location')
    status = data.get('status')
    remark = data.get('remark')

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT instrument_id FROM instruments WHERE barcode = %s", (barcode,))
            instrument = cursor.fetchone()
            cursor.execute("SELECT set_id FROM instrument_sets WHERE barcode = %s", (barcode,))
            set_ = cursor.fetchone()

            if not instrument and not set_:
                return jsonify({'message': 'Barcode not found'}), 404

            cursor.execute(
                "INSERT INTO tracking_log (set_id, instrument_id, action, location, status, remark, user_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (set_['set_id'] if set_ else None, instrument['instrument_id'] if instrument else None, action, location, status, remark, user_id)
            )
            if set_ and (status or location):
                cursor.execute(
                    "UPDATE instrument_sets SET status = COALESCE(%s, status), location = COALESCE(%s, location) WHERE set_id = %s",
                    (status, location, set_['set_id'])
                )
        conn.commit()
        return jsonify({'message': 'Scan logged successfully'})
    finally:
        conn.close()

# ======= SUMMARY UPLOAD ROUTE =======
@app.route('/upload-summary', methods=['POST'])
@role_required(['admin', 'staff'])
def upload_summary():
    data = request.form
    set_id = data.get('set_id')
    items = request.form.getlist('items[]')

    if not set_id or not items:
        return jsonify({'message': 'Missing required fields'}), 400

    try:
        items = [eval(item) for item in items]
    except:
        return jsonify({'message': 'Invalid items format'}), 400

    user_id = request.headers.get('User-ID')
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            for item in items:
                cursor.execute(
                    "UPDATE set_items SET actual_count = %s WHERE set_id = %s AND instrument_id = %s",
                    (item['actual_count'], set_id, item['instrument_id'])
                )
            cursor.execute(
                "SELECT SUM(expected_count = actual_count) AS matches, COUNT(*) AS total FROM set_items WHERE set_id = %s",
                (set_id,)
            )
            result = cursor.fetchone()
            condition_status = 'ok' if result['matches'] == result['total'] else 'not_ok'
            cursor.execute(
                "UPDATE instrument_sets SET condition_status = %s WHERE set_id = %s",
                (condition_status, set_id)
            )
            cursor.execute(
                "INSERT INTO tracking_log (set_id, action, user_id, remark) VALUES (%s, %s, %s, %s)",
                (set_id, 'upload_summary', user_id, 'Summary uploaded')
            )
        conn.commit()
        return jsonify({'message': 'Summary uploaded successfully', 'condition_status': condition_status})
    finally:
        conn.close()
