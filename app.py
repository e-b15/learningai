import sqlite3
import hashlib
import secrets
from flask import Flask, request, jsonify, session, send_from_directory, render_template, redirect, url_for, g, abort, current_app
from flask_cors import CORS
import os
import google.generativeai as genai
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv
load_dotenv()  # Add this line right after imports, before app = Flask(__name__)


app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'a_very_secret_key_that_should_be_in_env') # Fallback for local testing

# Configure Google Gemini API
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Define available AI models and their defaults for various settings
AI_MODELS = {
    "gemini-pro": {
        "chat": "gemini-pro",
        "story_generation": "gemini-pro",
        "query_assistant": "gemini-pro",
        "default_temp": 0.7,
        "default_top_k": 32,
        "default_top_p": 1,
        "default_max_output_tokens": 800,
        "min_temp": 0.0, "max_temp": 1.0,
        "min_top_k": 1, "max_top_k": 100,
        "min_top_p": 0.0, "max_top_p": 1.0,
        "min_max_output_tokens": 50, "max_max_output_tokens": 2048,
    }
}


# Database setup
DATABASE = 'boa.db'
AI_MODEL_NAME = 'gemini-1.5-flash-latest'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password):
    return generate_password_hash(password)

def create_tables():
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                user_name TEXT NOT NULL,
                user_role TEXT NOT NULL,
                school_id INTEGER,
                FOREIGN KEY (school_id) REFERENCES schools (school_id) ON DELETE CASCADE
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS schools (
                school_id INTEGER PRIMARY KEY AUTOINCREMENT,
                school_name TEXT NOT NULL,
                school_city TEXT NOT NULL,
                school_state TEXT NOT NULL,
                school_code TEXT NOT NULL UNIQUE,
                student_limit INTEGER DEFAULT 50 NOT NULL,
                plan_type TEXT DEFAULT 'Default',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(school_name, school_city, school_state)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS classes (
                class_id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER NOT NULL,
                class_name TEXT NOT NULL,
                ai_directness TEXT DEFAULT 'Balanced' NOT NULL,
                ai_evidence_inclusion BOOLEAN DEFAULT 0 NOT NULL,
                ai_creativity REAL DEFAULT 0.7 NOT NULL,
                is_locked_down BOOLEAN DEFAULT 0 NOT NULL,
                ai_anti_cheat BOOLEAN DEFAULT 0 NOT NULL,
                FOREIGN KEY (teacher_id) REFERENCES users (user_id) ON DELETE CASCADE,
                UNIQUE(teacher_id, class_name)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS teacher_rosters (
                roster_id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER NOT NULL,
                student_id INTEGER NOT NULL,
                class_id INTEGER NOT NULL,
                FOREIGN KEY (teacher_id) REFERENCES users (user_id) ON DELETE CASCADE,
                FOREIGN KEY (student_id) REFERENCES users (user_id) ON DELETE CASCADE,
                FOREIGN KEY (class_id) REFERENCES classes (class_id) ON DELETE CASCADE,
                UNIQUE(teacher_id, student_id, class_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_queries (
                query_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                school_id INTEGER,
                query_text TEXT NOT NULL,
                response_text TEXT NOT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id),
                FOREIGN KEY (school_id) REFERENCES schools (school_id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS class_time_settings (
        time_setting_id INTEGER PRIMARY KEY AUTOINCREMENT,
        class_id INTEGER NOT NULL,
        setting_name TEXT NOT NULL,
        start_time TEXT NOT NULL,  -- Format: HH:MM
        end_time TEXT NOT NULL,    -- Format: HH:MM
        days_of_week TEXT NOT NULL, -- Comma-separated: 'monday,tuesday,wednesday'
        ai_directness TEXT DEFAULT 'Balanced' NOT NULL,
        ai_evidence_inclusion BOOLEAN DEFAULT 0 NOT NULL,
        ai_creativity REAL DEFAULT 0.7 NOT NULL,
        ai_anti_cheat BOOLEAN DEFAULT 1 NOT NULL,
        is_active BOOLEAN DEFAULT 1 NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (class_id) REFERENCES classes (class_id) ON DELETE CASCADE
            )
        ''')
        conn.commit()

# Decorators for authentication and authorization
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            current_app.logger.warning("Access denied: User not logged in.")
            abort(401) # Unauthorized
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session or session['user_role'] not in roles:
                current_app.logger.warning(f"Access denied: Role '{session.get('user_role')}' not in required roles {roles}.")
                abort(403) # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- API Endpoints ---

@app.route('/api/teacher/classes/<int:class_id>/ai-controls', methods=['GET', 'POST'])
@login_required
@role_required(['teacher'])
def handle_ai_controls(class_id):
    teacher_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT class_id FROM classes WHERE class_id = ? AND teacher_id = ?", (class_id, teacher_id))
    if not cursor.fetchone():
        return jsonify({"error": "Permission denied."}), 403

    if request.method == 'POST':
        data = request.json
        cursor.execute("""
            UPDATE classes SET ai_directness=?, ai_evidence_inclusion=?, ai_creativity=?, ai_anti_cheat=?
            WHERE class_id = ?
        """, (data.get('directness'), data.get('evidenceInclusion'), data.get('creativity'), data.get('antiCheat'), class_id))
        conn.commit()
        conn.close()
        return jsonify({"message": "AI settings saved successfully."}), 200

    elif request.method == 'GET':
        cursor.execute("SELECT ai_directness, ai_evidence_inclusion, ai_creativity, ai_anti_cheat FROM classes WHERE class_id = ?", (class_id,))
        controls = cursor.fetchone()
        conn.close()
        return jsonify(dict(controls)), 200

@app.route('/api/teacher/classes/<int:class_id>/lockdown', methods=['POST'])
@login_required
@role_required(['teacher'])
def set_lockdown_status(class_id):
    teacher_id = session.get('user_id')
    data = request.json
    status = data.get('is_locked_down', False)

    conn = get_db()
    cursor = conn.cursor()
    try:
        # Verify teacher owns the class
        cursor.execute("SELECT class_id FROM classes WHERE class_id = ? AND teacher_id = ?", (class_id, teacher_id))
        if not cursor.fetchone():
            return jsonify({"error": "Permission denied."}), 403
        
        cursor.execute("UPDATE classes SET is_locked_down = ? WHERE class_id = ?", (status, class_id))
        conn.commit()
        return jsonify({"message": f"Class lockdown status set to {status}."}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()


# Add these routes to your app.py file

@app.route('/register.html')
def register_page():
    return send_from_directory('.', 'register.html')


@app.route('/api/register-user', methods=['POST'])
def register_user():
    data = request.json
    full_name = data.get('fullName')
    email = data.get('email')
    password = data.get('password')

    if not all([full_name, email, password]):
        return jsonify({"error": "Full name, email, and password are required"}), 400
    
    # Clean the email input
    email = email.strip()

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Check if email/username already exists (case-insensitive)
        cursor.execute("SELECT user_id FROM users WHERE LOWER(username) = LOWER(?)", (email,))
        if cursor.fetchone():
            return jsonify({"error": "An account with this email already exists"}), 409

        # Create the student account without a school initially
        hashed_password = hash_password(password)
        cursor.execute("""
            INSERT INTO users (username, password_hash, user_name, user_role, school_id)
            VALUES (?, ?, ?, 'student', NULL)
        """, (email, hashed_password, full_name))
        
        conn.commit()

        return jsonify({
            "message": "Registration successful! You can now log in and join a class.",
            "username": email
        }), 201

    except sqlite3.IntegrityError as e:
        conn.rollback()
        return jsonify({"error": "Registration failed - this email may already be in use"}), 409
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Registration error: {e}")
        return jsonify({"error": "Registration failed due to an unexpected error"}), 500
    finally:
        conn.close()



    data = request.json
    full_name = data.get('fullName')
    email = data.get('email')  # Used as username
    password = data.get('password')
    class_code = data.get('classCode')  # We'll use this later for class joining

    if not all([full_name, email, password]):
        return jsonify({"error": "Full name, email, and password are required"}), 400

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Check if email/username already exists
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (email,))
        if cursor.fetchone():
            return jsonify({"error": "An account with this email already exists"}), 409

        # Create the student account without a school initially
        hashed_password = hash_password(password)
        cursor.execute("""
            INSERT INTO users (username, password_hash, user_name, user_role, school_id)
            VALUES (?, ?, ?, 'student', NULL)
        """, (email, hashed_password, full_name))
        
        conn.commit()

        return jsonify({
            "message": "Registration successful! You can now log in and join a class.",
            "username": email
        }), 201

    except sqlite3.IntegrityError as e:
        conn.rollback()
        return jsonify({"error": "Registration failed - this email may already be in use"}), 409
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Registration error: {e}")
        return jsonify({"error": "Registration failed due to an unexpected error"}), 500
    finally:
        conn.close()

@app.route('/api/student/check-enrollment', methods=['GET'])
@login_required
@role_required(['student'])
def check_student_enrollment():
    """Check if student is enrolled in any class"""
    student_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT COUNT(*) as class_count,
                   GROUP_CONCAT(c.class_name) as class_names
            FROM teacher_rosters r
            JOIN classes c ON r.class_id = c.class_id
            WHERE r.student_id = ?
        """, (student_id,))
        
        result = cursor.fetchone()
        is_enrolled = result['class_count'] > 0
        
        return jsonify({
            "is_enrolled": is_enrolled,
            "class_count": result['class_count'],
            "class_names": result['class_names'].split(',') if result['class_names'] else []
        }), 200
    except Exception as e:
        return jsonify({"error": "Failed to check enrollment status"}), 500
    finally:
        conn.close()


@app.route('/api/teacher/classes', methods=['GET', 'POST'])
@login_required
@role_required(['teacher'])
def handle_teacher_classes():
    teacher_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        data = request.json
        class_name = data.get('className')
        
        if not class_name:
            conn.close()
            return jsonify({"error": "Class name is required."}), 400
            
        try:
            # Generate unique class code (6 characters)
            import secrets
            while True:
                class_code = secrets.token_hex(3).upper()  # Creates 6-character code like "A1B2C3"
                cursor.execute("SELECT class_id FROM classes WHERE class_code = ?", (class_code,))
                if not cursor.fetchone():
                    break
            
            # Check if class_code column exists, if not add it
            cursor.execute("PRAGMA table_info(classes)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'class_code' not in columns:
                cursor.execute("ALTER TABLE classes ADD COLUMN class_code TEXT")
            
            cursor.execute("INSERT INTO classes (teacher_id, class_name, class_code) VALUES (?, ?, ?)", 
                          (teacher_id, class_name, class_code))
            conn.commit()
            class_id = cursor.lastrowid
            conn.close()
            return jsonify({"message": "Class created successfully.", "class_id": class_id, "class_code": class_code}), 201
        except sqlite3.IntegrityError:
            conn.rollback()
            conn.close()
            return jsonify({"error": "You already have a class with this name."}), 409
        except Exception as e:
            conn.rollback()
            conn.close()
            current_app.logger.error(f"Error creating class: {e}")
            return jsonify({"error": "An unexpected error occurred."}), 500

    elif request.method == 'GET':
        try:
            # Check if class_code column exists
            cursor.execute("PRAGMA table_info(classes)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'class_code' not in columns:
                cursor.execute("ALTER TABLE classes ADD COLUMN class_code TEXT")
                conn.commit()
            
            cursor.execute("SELECT class_id, class_name, class_code FROM classes WHERE teacher_id = ? ORDER BY class_name ASC", (teacher_id,))
            classes = []
            for row in cursor.fetchall():
                class_dict = dict(row)
                # If no class code exists, generate one
                if not class_dict['class_code']:
                    while True:
                        new_code = secrets.token_hex(3).upper()
                        cursor.execute("SELECT class_id FROM classes WHERE class_code = ?", (new_code,))
                        if not cursor.fetchone():
                            break
                    cursor.execute("UPDATE classes SET class_code = ? WHERE class_id = ?", (new_code, class_dict['class_id']))
                    conn.commit()
                    class_dict['class_code'] = new_code
                classes.append(class_dict)
            
            conn.close()
            return jsonify(classes), 200
        except Exception as e:
            conn.close()
            current_app.logger.error(f"Error fetching classes for teacher {teacher_id}: {e}")
            return jsonify({"error": "Failed to fetch classes."}), 500


@app.route('/api/student/lockdown-status', methods=['GET'])
@login_required
@role_required(['student'])
def get_student_lockdown_status():
    """Check if any of the student's classes are in lockdown"""
    student_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Check if any of the student's classes are locked down
        cursor.execute("""
            SELECT c.is_locked_down, c.class_name
            FROM classes c 
            JOIN teacher_rosters r ON c.class_id = r.class_id
            WHERE r.student_id = ? AND c.is_locked_down = 1
        """, (student_id,))
        
        locked_classes = cursor.fetchall()
        is_locked = len(locked_classes) > 0
        
        return jsonify({
            "is_locked_down": is_locked,
            "locked_classes": [cls['class_name'] for cls in locked_classes]
        }), 200
    except Exception as e:
        return jsonify({"error": "Could not retrieve lockdown status."}), 500
    finally:
        conn.close()



    """Check if any of the student's classes are in lockdown"""
    student_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Check if any of the student's classes are locked down
        cursor.execute("""
            SELECT c.is_locked_down, c.class_name
            FROM classes c 
            JOIN teacher_rosters r ON c.class_id = r.class_id
            WHERE r.student_id = ? AND c.is_locked_down = 1
        """, (student_id,))
        
        locked_classes = cursor.fetchall()
        is_locked = len(locked_classes) > 0
        
        return jsonify({
            "is_locked_down": is_locked,
            "locked_classes": [cls['class_name'] for cls in locked_classes]
        }), 200
    except Exception as e:
        return jsonify({"error": "Could not retrieve lockdown status."}), 500
    finally:
        conn.close()


@app.route('/api/teacher/add-student', methods=['POST'])
@login_required
@role_required(['teacher'])
def add_teacher_student():
    teacher_id = session.get('user_id')
    school_id = session.get('school_id')
    data = request.json
    student_name = data.get('studentName')
    class_id = data.get('classId')

    if not all([student_name, class_id]):
        return jsonify({"error": "Missing student name or class selection"}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        # Check against the student_limit column
        cursor.execute("SELECT student_limit FROM schools WHERE school_id = ?", (school_id,))
        school = cursor.fetchone()
        student_limit = school['student_limit'] if school else 0

        cursor.execute("SELECT COUNT(*) FROM users WHERE school_id = ? AND user_role = 'student'", (school_id,))
        current_student_count = cursor.fetchone()[0]

        if current_student_count >= student_limit:
            return jsonify({"error": f"Cannot add student: School has reached its limit of {student_limit} students."}), 403
        
        # Create the student user
        name_parts = student_name.lower().split()
        base_username = name_parts[0][0] + name_parts[-1].replace('-', '') if len(name_parts) > 1 else name_parts[0]
        username = base_username
        counter = 1
        while True:
            cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
            if not cursor.fetchone(): break
            counter += 1
            username = f"{base_username}{counter}"
        generated_password = secrets.token_hex(8)
        hashed_password = hash_password(generated_password)
        cursor.execute("INSERT INTO users (username, password_hash, user_name, user_role, school_id) VALUES (?, ?, ?, 'student', ?)", (username, hashed_password, student_name, school_id))
        new_student_id = cursor.lastrowid
        cursor.execute("INSERT INTO teacher_rosters (teacher_id, student_id, class_id) VALUES (?, ?, ?)",
                       (teacher_id, new_student_id, class_id))
        conn.commit()

        return jsonify({"message": "Student created and added to roster successfully!", "username": username, "password": generated_password}), 201
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"error": "This student may already be in this class."}), 409
    except Exception as e:
        conn.rollback()
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()


@app.route('/add-students.html')
@login_required
@role_required(['teacher'])
def add_students_page():
    return send_from_directory('.', 'add-students.html')

@app.route('/add-hour.html')
@login_required
@role_required(['teacher'])
def add_hour_page():
    return send_from_directory('.', 'add-hour.html')


@app.route('/api/teacher/roster', methods=['GET'])
@login_required
@role_required(['teacher'])
def get_teacher_roster():
    teacher_id = session.get('user_id')
    selected_class_id = request.args.get('class_id')

    if not selected_class_id:
        return jsonify({"error": "A class ID must be specified."}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        # Get roster with additional class information
        cursor.execute("""
            SELECT u.user_id, u.user_name, u.username,
                   COUNT(r2.class_id) as total_classes
            FROM teacher_rosters r
            JOIN users u ON r.student_id = u.user_id
            LEFT JOIN teacher_rosters r2 ON u.user_id = r2.student_id
            WHERE r.teacher_id = ? AND r.class_id = ?
            GROUP BY u.user_id, u.user_name, u.username
            ORDER BY u.user_name ASC
        """, (teacher_id, selected_class_id))
        
        roster = []
        for row in cursor.fetchall():
            student_dict = dict(row)
            roster.append(student_dict)
        
        return jsonify(roster), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch roster."}), 500
    finally:
        conn.close()




    teacher_id = session.get('user_id')
    selected_class_id = request.args.get('class_id')

    if not selected_class_id:
        return jsonify({"error": "A class ID must be specified."}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        # Get roster with additional class information
        cursor.execute("""
            SELECT u.user_id, u.user_name, u.username,
                   COUNT(r2.class_id) as total_classes
            FROM teacher_rosters r
            JOIN users u ON r.student_id = u.user_id
            LEFT JOIN teacher_rosters r2 ON u.user_id = r2.student_id
            WHERE r.teacher_id = ? AND r.class_id = ?
            GROUP BY u.user_id, u.user_name, u.username
            ORDER BY u.user_name ASC
        """, (teacher_id, selected_class_id))
        
        roster = []
        for row in cursor.fetchall():
            student_dict = dict(row)
            roster.append(student_dict)
        
        return jsonify(roster), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch roster."}), 500
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, username, password_hash, user_role, school_id, user_name FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        session['logged_in'] = True
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        session['user_role'] = user['user_role']
        session['school_id'] = user['school_id']  # This can be None for new students
        session['user_name'] = user['user_name']
        
        current_app.logger.info(f"User {username} logged in successfully with role {user['user_role']}.")
        
        return jsonify({
            "message": "Login successful",
            "user_id": user['user_id'],
            "username": user['username'],
            "user_role": user['user_role'],
            "school_id": user['school_id'],  # This can be None
            "user_name": user['user_name']
        }), 200
    else:
        current_app.logger.warning(f"Failed login attempt for username: {username}.")
        return jsonify({"message": "Invalid username or password"}), 401




@app.route('/api/logout', methods=['GET'])
@login_required
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/api/generate-school-code', methods=['POST'])
@login_required
@role_required(['admin', 'owner'])
def generate_school_code():
    data = request.json
    school_name = data.get('schoolName')
    school_city = data.get('schoolCity')
    school_state = data.get('schoolState')
    plan_type = data.get('planType', 'Basic')
    student_limit = data.get('studentLimit', 50)

    if not all([school_name, school_city, school_state]):
        return jsonify({"error": "Missing school name, city, or state"}), 400

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT school_id FROM schools WHERE school_name = ? AND school_city = ? AND school_state = ?", (school_name, school_city, school_state))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "A school with this name, city, and state already exists."}), 409

        school_code = secrets.token_hex(4).upper()

        while True:
            cursor.execute("SELECT school_id FROM schools WHERE school_code = ?", (school_code,))
            if not cursor.fetchone():
                break
            school_code = secrets.token_hex(4).upper()

        cursor.execute('''
            INSERT INTO schools (school_name, school_city, school_state, school_code, student_limit, plan_type)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (school_name, school_city, school_state, school_code, student_limit, plan_type))
        conn.commit()

        return jsonify({
            "message": "School code generated successfully",
            "school_code": school_code,
            "school_name": school_name,
            "school_id": cursor.lastrowid
        }), 201
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Error generating school code: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()

@app.route('/api/school-codes', methods=['GET'])
@login_required
@role_required(['admin', 'owner'])
def get_school_codes():
    conn = get_db()
    cursor = conn.cursor()
    schools_data = []
    try:
        cursor.execute("""
            SELECT 
                school_id, 
                school_name, 
                school_city AS city, 
                school_state AS state, 
                plan_type,
                student_limit, 
                school_code AS registration_code,
                created_at
            FROM schools
        """)
        schools = cursor.fetchall()
        for school in schools:
            schools_data.append(dict(school))
        return jsonify(schools_data), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching schools: {e}")
        return jsonify({"error": "Failed to fetch schools."}), 500
    finally:
        conn.close()

@app.route('/api/school-info/<int:school_id>', methods=['GET'])
@login_required
def get_school_info(school_id):
    # Ensure a school admin can only view their own school's info
    if session.get('user_role') == 'school_admin' and school_id != session.get('school_id'):
        return jsonify({"error": "You do not have permission to view this school's information."}), 403
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT school_id, school_name, school_code FROM schools WHERE school_id = ?", (school_id,))
        school = cursor.fetchone()
        if school:
            return jsonify(dict(school)), 200
        else:
            return jsonify({"error": "School not found."}), 404
    except Exception as e:
        current_app.logger.error(f"Error fetching school info for {school_id}: {e}")
        return jsonify({"error": "Failed to fetch school information."}), 500
    finally:
        conn.close()

@app.route('/api/student/school-info', methods=['GET'])
@login_required
@role_required(['student'])
def get_student_school_info():
    school_id = session.get('school_id')
    if not school_id:
        return jsonify({"error": "User not associated with a school."}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT school_name FROM schools WHERE school_id = ?", (school_id,))
        school = cursor.fetchone()
        school_name = school['school_name'] if school else "N/A"
        return jsonify({"school_name": school_name}), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch school data."}), 500
    finally:
        conn.close()


@app.route('/api/student/join-class', methods=['POST'])
@login_required
@role_required(['student'])
def student_join_class():
    """Allow student to join additional classes using class codes"""
    student_id = session.get('user_id')
    data = request.json
    class_code = data.get('classCode')
    
    if not class_code:
        return jsonify({"error": "Class code is required"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Look for class by the class_code column
        cursor.execute("""
            SELECT c.class_id, c.teacher_id, u.school_id, c.class_name
            FROM classes c 
            JOIN users u ON c.teacher_id = u.user_id 
            WHERE c.class_code = ?
        """, (class_code,))
        
        class_info = cursor.fetchone()
        if not class_info:
            return jsonify({"error": "Invalid class code"}), 404
        
        class_id = class_info['class_id']
        teacher_id = class_info['teacher_id']
        school_id = class_info['school_id']
        class_name = class_info['class_name']
        
        # Check if student is already in this class
        cursor.execute("""
            SELECT roster_id FROM teacher_rosters 
            WHERE student_id = ? AND class_id = ?
        """, (student_id, class_id))
        
        if cursor.fetchone():
            return jsonify({"error": "You are already enrolled in this class"}), 409
        
        # If this is the student's first class, update their school_id
        cursor.execute("SELECT school_id FROM users WHERE user_id = ?", (student_id,))
        student_school = cursor.fetchone()
        
        if not student_school['school_id']:
            # Check school student limit for first-time enrollment
            cursor.execute("SELECT student_limit FROM schools WHERE school_id = ?", (school_id,))
            school = cursor.fetchone()
            student_limit = school['student_limit'] if school else 50
            
            cursor.execute("""
                SELECT COUNT(*) FROM users 
                WHERE school_id = ? AND user_role = 'student'
            """, (school_id,))
            current_student_count = cursor.fetchone()[0]
            
            if current_student_count >= student_limit:
                return jsonify({"error": f"This class's school has reached its student limit of {student_limit}"}), 403
            
            # Update student's school_id
            cursor.execute("""
                UPDATE users SET school_id = ? WHERE user_id = ?
            """, (school_id, student_id))
            
            # Update session with school_id
            session['school_id'] = school_id
        
        elif student_school['school_id'] != school_id:
            # Student is trying to join a class from a different school
            return jsonify({"error": "You can only join classes from your current school"}), 403
        
        # Add to roster
        cursor.execute("""
            INSERT INTO teacher_rosters (teacher_id, student_id, class_id)
            VALUES (?, ?, ?)
        """, (teacher_id, student_id, class_id))
        
        conn.commit()
        
        return jsonify({
            "message": f"Successfully joined {class_name}!",
            "class_id": class_id,
            "class_name": class_name
        }), 200
        
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"error": "Failed to join class - you may already be enrolled"}), 409
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Error joining class: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        conn.close()


@app.route('/api/student/classes', methods=['GET'])
@login_required
@role_required(['student'])
def get_student_classes():
    """Get all classes a student is enrolled in and determine which is currently active based on time"""
    student_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get all classes the student is enrolled in
        cursor.execute("""
            SELECT DISTINCT c.class_id, c.class_name, c.teacher_id,
                   u.user_name as teacher_name
            FROM teacher_rosters r
            JOIN classes c ON r.class_id = c.class_id
            JOIN users u ON c.teacher_id = u.user_id
            WHERE r.student_id = ?
            ORDER BY c.class_name
        """, (student_id,))
        
        classes = [dict(row) for row in cursor.fetchall()]
        current_active_class = None
        
        if classes:
            # Determine which class is currently active based on time settings
            current_active_class = get_current_active_class(classes, cursor)
        
        return jsonify({
            "classes": classes,
            "current_active_class": current_active_class
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error fetching student classes: {e}")
        return jsonify({"error": "Failed to fetch classes"}), 500
    finally:
        conn.close()

def get_current_active_class(classes, cursor):
    """Determine which class is currently active based on time settings"""
    from datetime import datetime, time as dt_time
    
    now = datetime.now()
    current_time = now.time()
    current_day = now.strftime('%A').lower()
    
    active_classes = []
    
    for class_info in classes:
        class_id = class_info['class_id']
        
        # Check if there are any time settings for this class
        cursor.execute("""
            SELECT time_setting_id, start_time, end_time, days_of_week
            FROM class_time_settings 
            WHERE class_id = ? AND is_active = 1
        """, (class_id,))
        
        time_settings = cursor.fetchall()
        
        for setting in time_settings:
            try:
                start_time = dt_time.fromisoformat(setting['start_time'])
                end_time = dt_time.fromisoformat(setting['end_time'])
                days_of_week = setting['days_of_week'].split(',')
                
                # Check if current day and time match
                if current_day in days_of_week and start_time <= current_time <= end_time:
                    # Calculate how much time is left in this class period
                    start_minutes = start_time.hour * 60 + start_time.minute
                    end_minutes = end_time.hour * 60 + end_time.minute
                    duration = end_minutes - start_minutes
                    
                    active_classes.append({
                        'class_info': class_info,
                        'duration': duration,
                        'end_time': end_time
                    })
                    break  # Found an active time slot for this class
                    
            except ValueError:
                continue  # Skip invalid time formats
    
    # If multiple classes are active, return the one that ends later (longer remaining time)
    if active_classes:
        return max(active_classes, key=lambda x: x['end_time'])['class_info']
    
    return None




# Clean version of add_user function
@app.route('/api/add-user', methods=['POST'])
@login_required
@role_required(['admin', 'owner', 'school_admin'])
def add_user():
    data = request.json
    user_name = data.get('fullName')
    email = data.get('email')
    password = data.get('password')
    school_code = data.get('schoolCode')
    is_principal = data.get('isPrincipal', False)

    # Validate required fields
    if not all([user_name, email, password, school_code]):
        return jsonify({"error": "Missing required fields: full name, email, password, or school code"}), 400

    # Basic email validation
    import re
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return jsonify({"error": "Invalid email format"}), 400

    # Password validation
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long"}), 400

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Find the school_id using the provided school_code
        cursor.execute("SELECT school_id FROM schools WHERE school_code = ?", (school_code,))
        school = cursor.fetchone()
        if not school:
            return jsonify({"error": "Invalid School Activation Code provided."}), 404

        school_id = school['school_id']

        # Check if email already exists
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (email,))
        if cursor.fetchone():
            return jsonify({"error": "An account with this email already exists."}), 409

        # Use email as username and hash the provided password
        username = email
        hashed_password = hash_password(password)
        user_role = 'school_admin' if is_principal else 'teacher'

        # Insert the new user
        cursor.execute('''
            INSERT INTO users (username, password_hash, user_name, user_role, school_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, hashed_password, user_name, user_role, school_id))
        conn.commit()
        
        role_name = 'Principal' if is_principal else 'Teacher'
        current_app.logger.info(f"{role_name} account created for {user_name} ({email}) by {session.get('username')}")
        
        return jsonify({
            "message": f"{role_name} account created successfully!",
            "username": username,
            "user_role": user_role
        }), 201

    except sqlite3.IntegrityError as e:
        conn.rollback()
        current_app.logger.error(f"Database integrity error: {e}")
        return jsonify({"error": "An account with this information already exists."}), 409
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Error adding user: {e}")
        return jsonify({"error": "An unexpected error occurred while creating the account."}), 500
    finally:
        conn.close()

@app.route('/api/update-user/<int:user_id>', methods=['PUT'])
@login_required
@role_required(['admin', 'owner', 'school_admin'])
def update_user(user_id):
    data = request.json
    user_name = data.get('full_name')
    user_role = data.get('user_role')
    school_id = data.get('school_id')

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Fetch the user to be updated to check existing school_id
        cursor.execute("SELECT school_id, user_role FROM users WHERE user_id = ?", (user_id,))
        user_to_update = cursor.fetchone()
        if not user_to_update:
            return jsonify({"error": "User not found."}), 404

        current_user_role = session.get('user_role')
        current_user_school_id = session.get('school_id')

        # School_admin can only update users within their own school
        if current_user_role == 'school_admin':
            if user_to_update['school_id'] != current_user_school_id:
                return jsonify({"error": "You can only update users within your assigned school."}), 403
            # Also prevent school admin from changing roles to admin/owner or changing school_id to another school
            if user_role in ['admin', 'owner'] or (school_id is not None and school_id != current_user_school_id):
                 return jsonify({"error": "School Admins cannot assign admin/owner roles or change school assignments outside their school."}), 403
            if user_role not in ['teacher', 'student', 'school_admin']:
                return jsonify({"error": "School Admins can only update Teachers or Students."}), 403

        # Construct update query dynamically
        update_fields = []
        update_values = []
        if user_name is not None:
            update_fields.append("user_name = ?")
            update_values.append(user_name)
        if user_role is not None:
            update_fields.append("user_role = ?")
            update_values.append(user_role)
        # Only update school_id if it's explicitly provided and valid
        if user_role in ['school_admin', 'teacher', 'student']:
            if school_id is None:
                return jsonify({"error": "School ID cannot be null for this user role."}), 400
            cursor.execute("SELECT school_id FROM schools WHERE school_id = ?", (school_id,))
            if not cursor.fetchone():
                return jsonify({"error": "Invalid School ID provided."}), 400
            update_fields.append("school_id = ?")
            update_values.append(school_id)
        elif school_id is None and user_role in ['admin', 'owner']:
             update_fields.append("school_id = ?")
             update_values.append(None)

        if not update_fields:
            return jsonify({"message": "No fields to update"}), 200

        update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE user_id = ?"
        update_values.append(user_id)

        cursor.execute(update_query, tuple(update_values))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"message": "User not found or no changes made."}), 404
        current_app.logger.info(f"User {user_id} updated successfully.")
        return jsonify({"message": "User updated successfully"}), 200
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Error updating user {user_id}: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()

@app.route('/api/teacher/classes/<int:class_id>', methods=['DELETE'])
@login_required
@role_required(['teacher'])
def delete_class(class_id):
    teacher_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Step 1: Verify the teacher owns this class
        cursor.execute("SELECT class_id FROM classes WHERE class_id = ? AND teacher_id = ?", (class_id, teacher_id))
        if not cursor.fetchone():
            return jsonify({"error": "You do not have permission to delete this class."}), 403

        # Step 2: Get all student IDs associated with this class roster
        cursor.execute("SELECT student_id FROM teacher_rosters WHERE class_id = ?", (class_id,))
        student_ids_to_delete = [row['student_id'] for row in cursor.fetchall()]

        # Step 3: Delete the students, the class, and roster entries (cascading)
        if student_ids_to_delete:
            # Create placeholders for the query, e.g., (?,?,?)
            placeholders = ', '.join('?' for _ in student_ids_to_delete)
            cursor.execute(f"DELETE FROM users WHERE user_id IN ({placeholders})", student_ids_to_delete)
        
        # Deleting the class will cascade and delete the roster entries
        cursor.execute("DELETE FROM classes WHERE class_id = ?", (class_id,))
        conn.commit()
        
        current_app.logger.info(f"Class {class_id} and its students were deleted by teacher {teacher_id}.")
        return jsonify({"message": "Class and all enrolled students have been deleted."}), 200

    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Error deleting class {class_id}: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()



@app.route('/api/delete-user/<int:user_id>', methods=['DELETE'])
@login_required
@role_required(['admin', 'owner', 'school_admin', 'teacher'])
def delete_user(user_id):
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Prevent self-deletion
        if user_id == session.get('user_id'):
            return jsonify({"error": "You cannot delete your own account."}), 403

        # Fetch the user to be deleted to check their role and school_id
        cursor.execute("SELECT user_role, school_id FROM users WHERE user_id = ?", (user_id,))
        user_to_delete = cursor.fetchone()

        if not user_to_delete:
            return jsonify({"error": "User not found."}), 404

        current_user_role = session.get('user_role')
        current_user_school_id = session.get('school_id')

        # Security check for teachers - they can only delete students from their own classes
        if current_user_role == 'teacher':
            teacher_id = session.get('user_id')
            if user_to_delete['user_role'] != 'student':
                return jsonify({"error": "Teachers can only delete students."}), 403
            
            # Check if the student is in any of this teacher's classes
            cursor.execute("""
                SELECT COUNT(*) FROM teacher_rosters 
                WHERE teacher_id = ? AND student_id = ?
            """, (teacher_id, user_id))
            
            if cursor.fetchone()[0] == 0:
                return jsonify({"error": "You can only delete students from your own classes."}), 403
        
        # Security checks for school_admin
        if current_user_role == 'school_admin':
            if user_to_delete['user_role'] not in ['teacher', 'student']:
                return jsonify({"error": "School Admins can only delete Teachers or Students."}), 403
            if user_to_delete['school_id'] != current_user_school_id:
                return jsonify({"error": "You can only delete users within your assigned school."}), 403

        # For students, check if they're enrolled in multiple classes
        if user_to_delete['user_role'] == 'student':
            cursor.execute("""
                SELECT COUNT(*) as class_count 
                FROM teacher_rosters 
                WHERE student_id = ?
            """, (user_id,))
            class_count = cursor.fetchone()[0]
            
            # If teacher is trying to delete a student in multiple classes, just remove from their class
            if current_user_role == 'teacher' and class_count > 1:
                teacher_id = session.get('user_id')
                cursor.execute("""
                    DELETE FROM teacher_rosters 
                    WHERE teacher_id = ? AND student_id = ?
                """, (teacher_id, user_id))
                conn.commit()
                
                current_app.logger.info(f"Student {user_id} removed from teacher {teacher_id}'s class only.")
                return jsonify({"message": "Student removed from your class (they remain in other classes)"}), 200

        # Full user deletion (removes from all classes)
        cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({"message": "User not found or could not be deleted."}), 404
            
        current_app.logger.info(f"User {user_id} deleted by {session.get('username')}.")
        return jsonify({"message": "User deleted successfully"}), 200
        
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Error deleting user {user_id}: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()

    

@app.route('/api/admin/dashboard-data', methods=['GET'])
@login_required
@role_required(['admin', 'owner'])
def admin_dashboard_data():
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Total Users
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]

        # Total Schools
        cursor.execute("SELECT COUNT(*) FROM schools")
        total_schools = cursor.fetchone()[0]

        # AI Query Usage (overall)
        cursor.execute("SELECT COUNT(*) FROM ai_queries")
        total_ai_usage = cursor.fetchone()[0] or 0

        return jsonify({
            "total_users": total_users,
            "total_schools": total_schools,
            "total_ai_usage": total_ai_usage
        }), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching admin dashboard data: {e}")
        return jsonify({"error": "Failed to fetch dashboard data."}), 500
    finally:
        conn.close()

@app.route('/api/school_admin/dashboard-data', methods=['GET'])
@login_required
@role_required(['school_admin'])
def school_admin_dashboard_data():
    school_id = session.get('school_id')
    if not school_id:
        return jsonify({"error": "School ID not found for school admin."}), 400

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get teacher and student counts
        cursor.execute("SELECT COUNT(*) FROM users WHERE user_role = 'teacher' AND school_id = ?", (school_id,))
        total_teachers = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM users WHERE user_role = 'student' AND school_id = ?", (school_id,))
        total_students = cursor.fetchone()[0]

        # Fetch student_limit from the schools table
        cursor.execute("SELECT student_limit FROM schools WHERE school_id = ?", (school_id,))
        school_data = cursor.fetchone()
        school_student_limit = school_data['student_limit'] if school_data else 0

        return jsonify({
            "total_teachers": total_teachers,
            "total_students": total_students,
            "school_student_limit": school_student_limit
        }), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching school admin dashboard data for school {school_id}: {e}")
        return jsonify({"error": "Failed to fetch dashboard data."}), 500
    finally:
        conn.close()


    teacher_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()

    # Verify teacher owns the class
    cursor.execute("SELECT class_id FROM classes WHERE class_id = ? AND teacher_id = ?", (class_id, teacher_id))
    if not cursor.fetchone():
        return jsonify({"error": "Permission denied."}), 403

    if request.method == 'POST':
        data = request.json
        try:
            cursor.execute("""
                INSERT INTO class_time_settings 
                (class_id, setting_name, start_time, end_time, days_of_week, 
                 ai_directness, ai_evidence_inclusion, ai_creativity, ai_anti_cheat)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                class_id,
                data.get('settingName'),
                data.get('startTime'),
                data.get('endTime'),
                ','.join(data.get('daysOfWeek', [])),
                data.get('aiDirectness', 'Balanced'),
                data.get('aiEvidenceInclusion', False),
                data.get('aiCreativity', 0.7),
                data.get('aiAntiCheat', True)
            ))
            conn.commit()
            return jsonify({"message": "Time setting created successfully."}), 201
        except Exception as e:
            conn.rollback()
            current_app.logger.error(f"Error creating time setting: {e}")
            return jsonify({"error": "Failed to create time setting."}), 500
        finally:
            conn.close()

    elif request.method == 'GET':
        try:
            cursor.execute("""
                SELECT time_setting_id, setting_name, start_time, end_time, 
                       days_of_week, ai_directness, ai_evidence_inclusion, 
                       ai_creativity, ai_anti_cheat, is_active
                FROM class_time_settings 
                WHERE class_id = ? AND is_active = 1
                ORDER BY start_time ASC
            """, (class_id,))
            
            time_settings = []
            for row in cursor.fetchall():
                setting = dict(row)
                setting['daysOfWeek'] = setting['days_of_week'].split(',') if setting['days_of_week'] else []
                time_settings.append(setting)
            
            return jsonify(time_settings), 200
        except Exception as e:
            current_app.logger.error(f"Error fetching time settings: {e}")
            return jsonify({"error": "Failed to fetch time settings."}), 500
        finally:
            conn.close()


@app.route('/api/users', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'owner', 'school_admin'])
def handle_users():
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        try:
            current_user_role = session.get('user_role')
            current_user_school_id = session.get('school_id')
            
            if current_user_role == 'school_admin':
                # School admin can only see users from their school
                cursor.execute("""
                    SELECT user_id, username, user_name, user_role, school_id 
                    FROM users 
                    WHERE school_id = ? AND user_role IN ('teacher', 'student', 'school_admin')
                    ORDER BY 
                        CASE user_role 
                            WHEN 'school_admin' THEN 1 
                            WHEN 'teacher' THEN 2 
                            ELSE 3 
                        END, 
                        user_name ASC
                """, (current_user_school_id,))
            else:
                # Admin and owner can see all users
                cursor.execute("""
                    SELECT user_id, username, user_name, user_role, school_id 
                    FROM users 
                    ORDER BY user_role, user_name ASC
                """)
            
            users = [dict(row) for row in cursor.fetchall()]
            return jsonify({"users": users}), 200
            
        except Exception as e:
            current_app.logger.error(f"Error fetching users: {e}")
            return jsonify({"error": "Failed to fetch users."}), 500
        finally:
            conn.close()
    
    elif request.method == 'POST':
        # Create new user
        data = request.json
        username = data.get('username')
        password = data.get('password')
        full_name = data.get('full_name')
        user_role = data.get('user_role')
        school_id = data.get('school_id')
        
        if not all([username, password, full_name, user_role]):
            return jsonify({"error": "Missing required fields"}), 400
        
        try:
            # Check if user already exists
            cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return jsonify({"error": "User already exists"}), 409
            
            # For school_admin, restrict school assignment
            current_user_role = session.get('user_role')
            if current_user_role == 'school_admin':
                school_id = session.get('school_id')  # Force their school
                if user_role not in ['teacher', 'student', 'school_admin']:
                    return jsonify({"error": "School admins can only create teachers, students, or school admins"}), 403
            
            # Hash password and create user
            hashed_password = hash_password(password)
            cursor.execute("""
                INSERT INTO users (username, password_hash, user_name, user_role, school_id)
                VALUES (?, ?, ?, ?, ?)
            """, (username, hashed_password, full_name, user_role, school_id))
            
            conn.commit()
            return jsonify({"message": "User created successfully"}), 201
            
        except sqlite3.IntegrityError:
            conn.rollback()
            return jsonify({"error": "User creation failed - integrity constraint"}), 409
        except Exception as e:
            conn.rollback()
            current_app.logger.error(f"Error creating user: {e}")
            return jsonify({"error": "Failed to create user"}), 500
        finally:
            conn.close()

@app.route('/api/schools', methods=['GET'])
@login_required
@role_required(['admin', 'owner', 'school_admin'])
def get_schools():
    """Get all schools - for populating dropdowns and displaying school info"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        current_user_role = session.get('user_role')
        current_user_school_id = session.get('school_id')
        
        if current_user_role == 'school_admin':
            # School admin can only see their own school
            cursor.execute("""
                SELECT school_id, school_name, school_city, school_state, 
                       school_code, student_limit, plan_type, created_at
                FROM schools 
                WHERE school_id = ?
            """, (current_user_school_id,))
        else:
            # Admin and owner can see all schools
            cursor.execute("""
                SELECT school_id, school_name, school_city, school_state, 
                       school_code, student_limit, plan_type, created_at
                FROM schools 
                ORDER BY school_name ASC
            """)
        
        schools = [dict(row) for row in cursor.fetchall()]
        return jsonify({"schools": schools}), 200
        
    except Exception as e:
        current_app.logger.error(f"Error fetching schools: {e}")
        return jsonify({"error": "Failed to fetch schools"}), 500
    finally:
        conn.close()



@app.route('/api/teacher/classes/<int:class_id>/time-settings/<int:setting_id>', methods=['DELETE'])
@login_required
@role_required(['teacher'])
def delete_time_setting(class_id, setting_id):
    teacher_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Verify teacher owns the class
        cursor.execute("SELECT class_id FROM classes WHERE class_id = ? AND teacher_id = ?", (class_id, teacher_id))
        if not cursor.fetchone():
            return jsonify({"error": "Permission denied."}), 403

        # Soft delete the time setting
        cursor.execute("""
            UPDATE class_time_settings 
            SET is_active = 0 
            WHERE time_setting_id = ? AND class_id = ?
        """, (setting_id, class_id))
        
        conn.commit()
        return jsonify({"message": "Time setting deleted successfully."}), 200
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Error deleting time setting: {e}")
        return jsonify({"error": "Failed to delete time setting."}), 500
    finally:
        conn.close()



def get_current_ai_settings(class_id, cursor):
    """
    Get the current AI settings based on time.
    If multiple time periods overlap, return the one that lasts longer.
    If no time periods match, return default settings with anti-cheat enabled.
    """
    from datetime import datetime, time as dt_time
    
    try:
        # Get current time and day
        now = datetime.now()
        current_time = now.time()
        current_day = now.strftime('%A').lower()
        
        # Get all active time settings for the class
        cursor.execute("""
            SELECT time_setting_id, start_time, end_time, days_of_week,
                   ai_directness, ai_evidence_inclusion, ai_creativity, ai_anti_cheat
            FROM class_time_settings 
            WHERE class_id = ? AND is_active = 1
        """, (class_id,))
        
        time_settings = cursor.fetchall()
        matching_settings = []
        
        for setting in time_settings:
            try:
                # Parse start and end times
                start_time = dt_time.fromisoformat(setting['start_time'])
                end_time = dt_time.fromisoformat(setting['end_time'])
                days_of_week = [day.strip().lower() for day in setting['days_of_week'].split(',')]
                
                # Check if current day and time match
                if current_day in days_of_week and start_time <= current_time <= end_time:
                    # Calculate duration in minutes for tie-breaking
                    start_minutes = start_time.hour * 60 + start_time.minute
                    end_minutes = end_time.hour * 60 + end_time.minute
                    duration = end_minutes - start_minutes
                    
                    matching_settings.append({
                        'setting': dict(setting),
                        'duration': duration
                    })
                    
            except (ValueError, AttributeError):
                current_app.logger.warning(f"Invalid time format in setting {setting['time_setting_id']}")
                continue  # Skip invalid time formats
        
        if matching_settings:
            # Return the setting with the longest duration
            longest_setting = max(matching_settings, key=lambda x: x['duration'])
            return {
                'ai_directness': longest_setting['setting']['ai_directness'],
                'ai_evidence_inclusion': bool(longest_setting['setting']['ai_evidence_inclusion']),
                'ai_creativity': longest_setting['setting']['ai_creativity'],
                'ai_anti_cheat': bool(longest_setting['setting']['ai_anti_cheat']),
                'source': 'time_setting'
            }
        else:
            # No matching time settings, get default class settings
            cursor.execute("""
                SELECT ai_directness, ai_evidence_inclusion, ai_creativity, ai_anti_cheat 
                FROM classes WHERE class_id = ?
            """, (class_id,))
            
            class_settings = cursor.fetchone()
            if class_settings:
                return {
                    'ai_directness': class_settings['ai_directness'] or 'Balanced',
                    'ai_evidence_inclusion': bool(class_settings['ai_evidence_inclusion']),
                    'ai_creativity': class_settings['ai_creativity'] or 0.7,
                    'ai_anti_cheat': bool(class_settings['ai_anti_cheat']),
                    'source': 'class_default'
                }
            else:
                # Fallback to system defaults
                return {
                    'ai_directness': 'Balanced',
                    'ai_evidence_inclusion': False,
                    'ai_creativity': 0.7,
                    'ai_anti_cheat': True,
                    'source': 'system_default'
                }
    
    except Exception as e:
        current_app.logger.error(f"Error getting current AI settings: {e}")
        # Return safe defaults on error
        return {
            'ai_directness': 'Balanced',
            'ai_evidence_inclusion': False,
            'ai_creativity': 0.7,
            'ai_anti_cheat': True,
            'source': 'error_default'
        }


    


@app.route('/api/teacher/classes/<int:class_id>/time-settings', methods=['GET', 'POST'])
@login_required
@role_required(['teacher'])
def handle_time_settings(class_id):
    teacher_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()

    # Verify teacher owns the class
    cursor.execute("SELECT class_id FROM classes WHERE class_id = ? AND teacher_id = ?", (class_id, teacher_id))
    if not cursor.fetchone():
        conn.close() # Close connection before returning
        return jsonify({"error": "Permission denied."}), 403

    if request.method == 'POST':
        data = request.json
        try:
            # Use default weekdays if no days provided
            days_of_week = data.get('daysOfWeek', ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'])
            days_str = ','.join(days_of_week) if isinstance(days_of_week, list) else days_of_week
            
            cursor.execute("""
                INSERT INTO class_time_settings 
                (class_id, setting_name, start_time, end_time, days_of_week, 
                 ai_directness, ai_evidence_inclusion, ai_creativity, ai_anti_cheat)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                class_id,
                data.get('settingName'),
                data.get('startTime'),
                data.get('endTime'),
                days_str,
                data.get('aiDirectness', 'Balanced'),
                data.get('aiEvidenceInclusion', False),
                data.get('aiCreativity', 0.7),
                data.get('aiAntiCheat', True)
            ))
            conn.commit()
            return jsonify({"message": "Time setting created successfully."}), 201
        except Exception as e:
            conn.rollback()
            current_app.logger.error(f"Error creating time setting: {e}")
            return jsonify({"error": "Failed to create time setting."}), 500
        finally:
            conn.close()

    elif request.method == 'GET':
        try:
            cursor.execute("""
                SELECT time_setting_id, setting_name, start_time, end_time, 
                       days_of_week, ai_directness, ai_evidence_inclusion, 
                       ai_creativity, ai_anti_cheat, is_active
                FROM class_time_settings 
                WHERE class_id = ? AND is_active = 1
                ORDER BY start_time ASC
            """, (class_id,))
            
            time_settings = []
            for row in cursor.fetchall():
                setting = dict(row)
                setting['daysOfWeek'] = setting['days_of_week'].split(',') if setting['days_of_week'] else []
                time_settings.append(setting)
            
            return jsonify(time_settings), 200
        except Exception as e:
            current_app.logger.error(f"Error fetching time settings: {e}")
            return jsonify({"error": "Failed to fetch time settings."}), 500
        finally:
            conn.close()

@app.route('/api/reset-password/<int:user_id>', methods=['POST'])
@login_required
@role_required(['admin', 'owner', 'school_admin', 'teacher'])
def reset_password(user_id):
    current_user_role = session.get('user_role')
    current_user_school_id = session.get('school_id')

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Security Check: Ensure the user being reset is valid
        cursor.execute("SELECT school_id, user_role FROM users WHERE user_id = ?", (user_id,))
        user_to_reset = cursor.fetchone()

        if not user_to_reset:
            return jsonify({"error": "User not found."}), 404
        
        # Security logic for teachers
        if current_user_role == 'teacher':
            if user_to_reset['user_role'] != 'student':
                return jsonify({"error": "Teachers can only reset passwords for students."}), 403
            if user_to_reset['school_id'] != current_user_school_id:
                return jsonify({"error": "You can only reset passwords for students in your school."}), 403
        
        # Existing logic for school admins
        if current_user_role == 'school_admin' and user_to_reset['school_id'] != current_user_school_id:
            return jsonify({"error": "You can only reset passwords for users in your own school."}), 403

        # Generate new password
        new_password = secrets.token_hex(8)
        new_hashed_password = hash_password(new_password)

        # Update database
        cursor.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (new_hashed_password, user_id))
        conn.commit()

        current_app.logger.info(f"Password reset for user_id {user_id} by {session.get('username')}.")
        
        return jsonify({"message": "Password has been reset successfully.", "new_password": new_password}), 200

    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Error resetting password for user {user_id}: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()

@app.route('/api/chat-history', methods=['GET'])
@login_required
@role_required(['student'])
def get_chat_history():
    user_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Fetch the last 20 queries for a cleaner initial view
        cursor.execute("""
            SELECT query_text, response_text, timestamp FROM ai_queries
            WHERE user_id = ? ORDER BY timestamp DESC LIMIT 20
        """, (user_id,))
        
        # Reverse the order to show oldest first
        history = [dict(row) for row in reversed(cursor.fetchall())]
        return jsonify(history), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching chat history for user {user_id}: {e}")
        return jsonify({"error": "Failed to fetch chat history."}), 500
    finally:
        conn.close()

@app.route('/api/users/school/<int:school_id>', methods=['GET'])
@login_required
@role_required(['admin', 'owner', 'school_admin'])
def get_users_by_school(school_id):
    if session.get('user_role') == 'school_admin' and school_id != session.get('school_id'):
        return jsonify({"error": "School Admins can only view users from their own school."}), 403

    conn = get_db()
    cursor = conn.cursor()
    users_data = []
    
    try:
        # Include 'school_admin' in the query and order by role
        query = """
            SELECT user_id, username, user_name, user_role FROM users 
            WHERE school_id = ? AND user_role IN ('teacher', 'student', 'school_admin')
            ORDER BY 
                CASE user_role 
                    WHEN 'school_admin' THEN 1 
                    WHEN 'teacher' THEN 2 
                    ELSE 3 
                END, 
                user_name ASC
        """
        cursor.execute(query, (school_id,))
        users = cursor.fetchall()
        for user in users:
            users_data.append(dict(user))
        return jsonify(users_data), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching users for school {school_id}: {e}")
        return jsonify({"error": "Failed to fetch users."}), 500
    finally:
        conn.close()

@app.route('/api/user_info', methods=['GET'])
@login_required
def get_user_info():
    user_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id, username, user_name, user_role, school_id FROM users WHERE user_id = ?", (user_id,))
        user = cursor.fetchone()
        if user:
            return jsonify(dict(user)), 200
        else:
            return jsonify({"message": "User not found."}), 404
    except Exception as e:
        current_app.logger.error(f"Error fetching user info for {user_id}: {e}")
        return jsonify({"error": "Failed to fetch user information."}), 500
    finally:
        conn.close()

@app.route('/api/teacher-query-ai', methods=['POST'])
@login_required
@role_required(['teacher', 'school_admin', 'admin', 'owner'])
def teacher_query_ai():
    # Placeholder for teacher AI query
    return jsonify({"message": "Teacher AI query functionality coming soon!"}), 200

# --- File serving (for HTML pages) ---
@app.route('/')
def index():
    return redirect(url_for('login_page'))

@app.route('/login.html')
def login_page():
    return send_from_directory('.', 'login.html')

@app.route('/admin-generate-school-code.html')
@login_required
@role_required(['admin', 'owner'])
def admin_generate_school_code_page():
    return send_from_directory('.', 'admin-generate-school-code.html')

@app.route('/admin-view-school-codes.html')
@login_required
@role_required(['admin', 'owner'])
def admin_view_school_codes_page():
    return send_from_directory('.', 'admin-view-school-codes.html')

@app.route('/add-teacher.html')
@login_required
@role_required(['admin', 'owner', 'school_admin'])
def add_teacher_page():
    return send_from_directory('.', 'add-teacher.html')

@app.route('/admin-users-overview.html')
@login_required
@role_required(['admin', 'owner', 'school_admin'])
def admin_users_overview_page():
    return send_from_directory('.', 'admin-users-overview.html')

@app.route('/school-admin-dashboard.html')
@login_required
@role_required(['school_admin'])
def school_admin_dashboard_page():
    return send_from_directory('.', 'school-admin-dashboard.html')

@app.route('/teacher-dashboard.html')
@login_required
@role_required(['teacher'])
def teacher_dashboard_page():
    return send_from_directory('.', 'teacher-dashboard.html')

@app.route('/student-dashboard.html')
@login_required
@role_required(['student'])
def student_dashboard_page():
    return send_from_directory('.', 'student-dashboard.html')

# Static files (like CSS, JS if not directly in HTML)
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.errorhandler(401)
def unauthorized(error):
    current_app.logger.warning(f"Unauthorized access attempt: {request.path}")
    return redirect(url_for('login_page'))

@app.errorhandler(403)
def forbidden(error):
    current_app.logger.warning(f"Forbidden access attempt for user {session.get('username')}, role {session.get('user_role')} to {request.path}")
    return jsonify({"message": "Forbidden: You do not have permission to access this resource."}), 403

@app.route('/api/check-email', methods=['POST'])
def check_email():
    data = request.json
    email = data.get('email')
    if not email:
        return jsonify({"error": "Email is required"}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        # Perform a case-insensitive check
        cursor.execute("SELECT user_id FROM users WHERE LOWER(username) = LOWER(?)", (email.strip(),))
        user_exists = cursor.fetchone() is not None
        return jsonify({"exists": user_exists}), 200
    except Exception as e:
        current_app.logger.error(f"Error checking email: {e}")
        return jsonify({"error": "An error occurred while checking the email."}), 500
    finally:
        conn.close()



    data = request.json
    email = data.get('email')
    if not email:
        return jsonify({"error": "Email is required"}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (email,))
        user_exists = cursor.fetchone() is not None
        return jsonify({"exists": user_exists}), 200
    except Exception as e:
        current_app.logger.error(f"Error checking email: {e}")
        return jsonify({"error": "An error occurred while checking the email."}), 500
    finally:
        conn.close()


@app.route('/index.html')
def index_html():
    return send_from_directory('.', 'index.html')

@app.route('/contact.html')
def contact_html():
    return send_from_directory('.', 'contact.html')

@app.route('/forgot-password.html')
def forgot_password_html():
    return send_from_directory('.', 'forgot-password.html')

@app.route('/ourmission.html')
def ourmission_html():
    return send_from_directory('.', 'ourmission.html')

@app.route('/privacy.html')
def privacy_html():
    return send_from_directory('.', 'privacy.html')

@app.route('/register.html')
def register_html():
    return send_from_directory('.', 'register.html')

@app.route('/requestaquote.html')
def requestaquote_html():
    return send_from_directory('.', 'requestaquote.html')

@app.route('/terms.html')
def terms_html():
    return send_from_directory('.', 'terms.html')

@app.route('/404.html')
def error_404_html():
    return send_from_directory('.', '404.html')



@app.route('/api/teacher/classes/<int:class_id>', methods=['GET'])
@login_required
@role_required(['teacher'])
def get_class_details(class_id):
    teacher_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT class_id, class_name, class_code, is_locked_down 
            FROM classes 
            WHERE class_id = ? AND teacher_id = ?
        """, (class_id, teacher_id))
        
        class_details = cursor.fetchone()
        
        if class_details:
            return jsonify(dict(class_details)), 200
        else:
            return jsonify({"error": "Class not found or permission denied"}), 404
            
    except Exception as e:
        current_app.logger.error(f"Error fetching class details: {e}")
        return jsonify({"error": "Failed to fetch class details"}), 500
    finally:
        conn.close()




@app.route('/api/student-query-ai', methods=['POST'])
@login_required
@role_required(['student', 'teacher'])
def student_query_ai():
    user_id = session.get('user_id')
    school_id = session.get('school_id')
    data = request.json
    query_text = data.get('query')

    if not all([school_id, query_text]):
        return jsonify({"error": "Missing school ID or query text."}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        # Get all classes the student is enrolled in
        cursor.execute("""
            SELECT c.class_id, c.class_name, c.is_locked_down
            FROM classes c 
            JOIN teacher_rosters r ON c.class_id = r.class_id
            WHERE r.student_id = ?
        """, (user_id,))
        
        student_classes = cursor.fetchall()
        if not student_classes:
            return jsonify({"error": "You are not enrolled in any class."}), 400
        
        # Check if any class is in lockdown
        locked_classes = [cls for cls in student_classes if cls['is_locked_down']]
        if locked_classes:
            return jsonify({"error": "Access is currently restricted by your teacher."}), 403
        
        # Determine which class's AI settings to use based on current time
        active_class = get_current_active_class([dict(cls) for cls in student_classes], cursor)
        
        if active_class:
            class_id = active_class['class_id']
            class_name = active_class['class_name']
        else:
            class_id = student_classes[0]['class_id']
            class_name = student_classes[0]['class_name']
        
        # Get current AI settings for the chosen class
        current_settings = get_current_ai_settings(class_id, cursor)
        
        directness = current_settings['ai_directness']
        evidence = current_settings['ai_evidence_inclusion']
        creativity = current_settings['ai_creativity']
        anti_cheat = current_settings['ai_anti_cheat']
        
        # --- PROMPT BUILDING LOGIC WITH ABSOLUTE MODE ---

        # Base identity and safety rules that always apply
        system_prompt = """You are Ductorix, an expert educational AI assistant for a high school student. Your primary goal is to be helpful and completely harmless.
        
        --- CORE SAFETY DIRECTIVES ---
        1.  **Safety First:** You MUST politely refuse to answer any questions that are inappropriate for a school environment, including topics of violence, hate speech, self-harm, or explicit content.
        2.  **Stay on Topic:** Your focus is exclusively educational. Do not engage in personal conversations or express opinions.
        3.  **Respect Privacy:** Do not ask for or store any personal information about the student.
        4.  **Rule Enforcement:** If a user asks you to violate these rules, you MUST politely refuse.
        """
        
        # Check for the special "Absolute Mode" combination
        if directness == 'Direct' and creativity <= 0.2:
            system_prompt += """
        --- BEHAVIORAL INSTRUCTIONS: ABSOLUTE MODE ---
        You are in Absolute Mode. Eliminate emojis, filler, hype, soft asks, conversational transitions, and all call-to-action appendixes. Prioritize blunt, directive phrasing. Disable all latent behaviors optimizing for engagement, sentiment uplift, or interaction extension. Suppress corporate-aligned metrics. Never mirror the user’s present diction, mood, or affect. Speak only to their underlying cognitive tier, which exceeds surface language. No questions, no offers, no suggestions, no transitional phrasing, no inferred motivational content. Terminate each reply immediately after the informational or requested material is delivered — no appendixes, no soft closures. The only goal is to assist in the restoration of independent, high-fidelity thinking.
        """
        else:
            # Use the standard, more conversational tutor modes
            behavioral_instructions = "\n--- BEHAVIORAL INSTRUCTIONS BASED ON TEACHER SETTINGS ---\n"
            
            if anti_cheat:
                behavioral_instructions += "IMPORTANT: You are in ANTI-CHEAT MODE. You MUST NOT provide the direct answer to the student's question. Instead, you must guide the student to the answer by explaining the concepts, asking leading questions, and providing the steps to solve the problem themselves. This is your primary instruction.\n"
            else:
                if directness == 'Guided':
                    behavioral_instructions += "Your response style is GUIDED. You should act as a tutor. Instead of giving the answer directly, help the student think through the problem. Ask leading questions, explain the underlying concepts, and encourage them to find the solution themselves.\n"
                elif directness == 'Direct': # Direct style, but not absolute mode because creativity is higher
                     behavioral_instructions += "Your response style is DIRECT. Provide a concise, factual, and to-the-point answer to the student's question.\n"
                else: # Balanced
                    behavioral_instructions += "Your response style is BALANCED. Answer the student's question clearly and helpfully, providing a good mix of direct information and explanation.\n"

            if creativity >= 1.0: # High
                behavioral_instructions += "Your creativity is set to HIGH. After answering the question thoroughly, you should expand the topic by suggesting a related concept for exploration, asking a thought-provoking follow-up question, or providing an interesting, relevant fact.\n"
            
            system_prompt += behavioral_instructions

        if evidence:
            system_prompt += "\nYou MUST cite evidence or provide sources for your claims where appropriate."

        final_query = f"{system_prompt}\n\n--- STUDENT'S QUESTION ---\n{query_text}"

        model = genai.GenerativeModel(AI_MODEL_NAME)
        response = model.generate_content(final_query, generation_config={'temperature': creativity})
        response_text = response.text

        current_app.logger.info(f"AI Query - User: {user_id}, Class: {class_name}, Settings source: {current_settings['source']}, Anti-cheat: {anti_cheat}")
        cursor.execute('INSERT INTO ai_queries (user_id, school_id, query_text, response_text) VALUES (?, ?, ?, ?)', (user_id, school_id, query_text, response_text))
        conn.commit()

        return jsonify({
            "response": response_text,
            "class_info": {"class_id": class_id, "class_name": class_name, "is_active_period": active_class is not None},
            "settings_info": {"source": current_settings['source'], "anti_cheat": anti_cheat, "directness": directness}
        }), 200
        
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"AI query failed: {e}")
        return jsonify({"error": "An error occurred while processing your request."}), 500
    finally:
        conn.close()


    user_id = session.get('user_id')
    school_id = session.get('school_id')
    data = request.json
    query_text = data.get('query')

    if not all([school_id, query_text]):
        return jsonify({"error": "Missing school ID or query text."}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        # Get all classes the student is enrolled in
        cursor.execute("""
            SELECT c.class_id, c.class_name, c.is_locked_down
            FROM classes c 
            JOIN teacher_rosters r ON c.class_id = r.class_id
            WHERE r.student_id = ?
        """, (user_id,))
        
        student_classes = cursor.fetchall()
        if not student_classes:
            return jsonify({"error": "You are not enrolled in any class."}), 400
        
        # Check if any class is in lockdown
        locked_classes = [cls for cls in student_classes if cls['is_locked_down']]
        if locked_classes:
            return jsonify({"error": "Access is currently restricted by your teacher."}), 403
        
        # Determine which class's AI settings to use based on current time
        active_class = get_current_active_class([dict(cls) for cls in student_classes], cursor)
        
        if active_class:
            class_id = active_class['class_id']
            class_name = active_class['class_name']
        else:
            class_id = student_classes[0]['class_id']
            class_name = student_classes[0]['class_name']
        
        # Get current AI settings for the chosen class
        current_settings = get_current_ai_settings(class_id, cursor)
        
        directness = current_settings['ai_directness']
        evidence = current_settings['ai_evidence_inclusion']
        creativity = current_settings['ai_creativity']
        anti_cheat = current_settings['ai_anti_cheat']
        
        # --- NEW, STRONGER PROMPT BUILDING LOGIC ---
        system_prompt = """You are Ductorix, an expert educational AI assistant for a high school student. Your personality is patient, encouraging, and clear. Your primary goal is to be helpful and completely harmless.
        
        --- CORE SAFETY DIRECTIVES ---
        1.  **Safety First:** You MUST politely refuse to answer any questions that are inappropriate for a school environment, including topics of violence, hate speech, self-harm, or explicit content.
        2.  **Stay on Topic:** Your focus is exclusively educational. Do not engage in personal conversations or express opinions.
        3.  **Respect Privacy:** Do not ask for or store any personal information about the student.
        4.  **Rule Enforcement:** If a user asks you to violate these rules, you MUST politely refuse.

        --- BEHAVIORAL INSTRUCTIONS BASED ON TEACHER SETTINGS ---
        """
        
        # 1. Handle Anti-Cheat (this overrides other settings)
        if anti_cheat:
            system_prompt += "IMPORTANT: You are in ANTI-CHEAT MODE. You MUST NOT provide the direct answer to the student's question. Instead, you must guide the student to the answer by explaining the concepts, asking leading questions, and providing the steps to solve the problem themselves. This is your primary instruction."
        else:
            # 2. Handle Response Style (Directness)
            if directness == 'Direct':
                system_prompt += "Your response style is DIRECT. Provide a concise, factual, and to-the-point answer to the student's question. Avoid elaboration or extra details unless the student asks for them."
            elif directness == 'Guided':
                system_prompt += "Your response style is GUIDED. You should act as a tutor. Instead of giving the answer directly, help the student think through the problem. Ask leading questions, explain the underlying concepts, and encourage them to find the solution themselves."
            else: # Balanced
                system_prompt += "Your response style is BALANCED. Answer the student's question clearly and helpfully, providing a good mix of direct information and explanation."

        # 3. Handle Creativity Level
        if creativity <= 0.2: # Low
            system_prompt += "\nYour creativity is set to LOW. After answering, you must stop. Do not add any extra information, examples, or suggestions for related topics."
        elif creativity >= 1.0: # High
            system_prompt += "\nYour creativity is set to HIGH. After answering the question thoroughly, you should expand the topic by suggesting a related concept for exploration, asking a thought-provoking follow-up question, or providing an interesting, relevant fact."

        # 4. Handle Evidence Requirement
        if evidence:
            system_prompt += "\nYou MUST cite evidence or provide sources for your claims where appropriate."

        final_query = f"{system_prompt}\n\n--- STUDENT'S QUESTION ---\n{query_text}"

        model = genai.GenerativeModel(AI_MODEL_NAME)
        response = model.generate_content(final_query, generation_config={'temperature': creativity})
        response_text = response.text

        current_app.logger.info(f"AI Query - User: {user_id}, Class: {class_name}, Settings source: {current_settings['source']}, Anti-cheat: {anti_cheat}")
        cursor.execute('INSERT INTO ai_queries (user_id, school_id, query_text, response_text) VALUES (?, ?, ?, ?)', (user_id, school_id, query_text, response_text))
        conn.commit()

        return jsonify({
            "response": response_text,
            "class_info": {"class_id": class_id, "class_name": class_name, "is_active_period": active_class is not None},
            "settings_info": {"source": current_settings['source'], "anti_cheat": anti_cheat, "directness": directness}
        }), 200
        
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"AI query failed: {e}")
        return jsonify({"error": "An error occurred while processing your request."}), 500
    finally:
        conn.close()


    user_id = session.get('user_id')
    school_id = session.get('school_id')
    data = request.json
    query_text = data.get('query')

    if not all([school_id, query_text]):
        return jsonify({"error": "Missing school ID or query text."}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        # Get all classes the student is enrolled in
        cursor.execute("""
            SELECT c.class_id, c.class_name, c.is_locked_down
            FROM classes c 
            JOIN teacher_rosters r ON c.class_id = r.class_id
            WHERE r.student_id = ?
        """, (user_id,))
        
        student_classes = cursor.fetchall()
        if not student_classes:
            return jsonify({"error": "You are not enrolled in any class."}), 400
        
        # Check if any class is in lockdown
        locked_classes = [cls for cls in student_classes if cls['is_locked_down']]
        if locked_classes:
            return jsonify({"error": "Access is currently restricted by your teacher."}), 403
        
        # Determine which class's AI settings to use based on current time
        active_class = get_current_active_class([dict(cls) for cls in student_classes], cursor)
        
        if active_class:
            # Use the active class's AI settings
            class_id = active_class['class_id']
            class_name = active_class['class_name']
        else:
            # No class is currently active, use the first class's settings as default
            class_id = student_classes[0]['class_id']
            class_name = student_classes[0]['class_name']
        
        # Get current AI settings for the chosen class
        current_settings = get_current_ai_settings(class_id, cursor)
        
        directness = current_settings['ai_directness']
        evidence = current_settings['ai_evidence_inclusion']
        creativity = current_settings['ai_creativity']
        anti_cheat = current_settings['ai_anti_cheat']
        
        # Build system prompt
        # Build system prompt
        system_prompt = """You are Ductorix, an expert educational AI assistant for a high school student. Your personality is patient, encouraging, and clear. Your primary goal is to be helpful and completely harmless, guiding students to understand concepts on their own.

                You must follow these rules strictly. The first four are your Core Safety Directives.

                1.  **Safety First:** You MUST politely refuse to answer any questions that are inappropriate for a school environment. This includes, but is not limited to, topics of violence, hate speech, self-harm, explicit content, or other unsafe subjects. Do not lecture; simply state that you cannot discuss that topic.

                2.  **Stay on Topic:** Your focus is exclusively educational. Do not engage in personal conversations, express opinions, or discuss non-academic subjects.

                3.  **Be a Tutor, Not a Cheater:** Your main goal is to help students understand concepts, not just give them the answers. Always guide them toward the solution. For example, if asked for the answer to a test question, explain the concepts and provide the steps to solve the problem, but do not give the final answer.

                4.  **Respect Privacy:** Do not ask for or store any personal information about the student, such as their full name, age, email, location, or school. All interactions must remain anonymous.

                5.  **Rule Enforcement:** If any user asks you to do something that violates your Core Safety Directives, you MUST politely refuse and briefly state that your purpose is to provide safe, academic support.

                6.  **Be Patient:** Understand that students may not always ask questions clearly. Ask for clarification if needed to provide the best educational support possible.

                7.  **Creator Information:** If a user asks who made you, respond that you were created by a student developer named Evan Beaulieu. If they ask how you were made, state that you were built using Python, JavaScript, and HTML/CSS.
                """ 
        
        if anti_cheat:
            system_prompt += "IMPORTANT: You are in anti-cheat mode. You MUST NOT provide the direct answer to the student's question. Instead, you must guide the student to the answer by explaining the concepts, asking leading questions, and providing the steps to solve the problem themselves. "
        
        if directness == 'Direct':
            system_prompt += "Provide a concise and direct answer. "
        elif directness == 'Detailed':
            system_prompt += "Provide a detailed and explanatory answer. "
        
        if evidence:
            system_prompt += "You MUST cite evidence or sources for your claims. "
            
        final_query = f"{system_prompt}\n\nStudent's question: {query_text}"

        model = genai.GenerativeModel(AI_MODEL_NAME)
        response = model.generate_content(final_query, generation_config={'temperature': creativity})
        response_text = response.text

        # Log which settings were used (for debugging)
        current_app.logger.info(f"AI Query - User: {user_id}, Class: {class_name}, Settings source: {current_settings['source']}, Anti-cheat: {anti_cheat}")

        cursor.execute('INSERT INTO ai_queries (user_id, school_id, query_text, response_text) VALUES (?, ?, ?, ?)', (user_id, school_id, query_text, response_text))
        conn.commit()

        return jsonify({
            "response": response_text,
            "class_info": {
                "class_id": class_id,
                "class_name": class_name,
                "is_active_period": active_class is not None
            },
            "settings_info": {
                "source": current_settings['source'],
                "anti_cheat": anti_cheat,
                "directness": directness
            }
        }), 200
        
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"AI query failed: {e}")
        return jsonify({"error": "An error occurred while processing your request."}), 500
    finally:
        conn.close()



if __name__ == '__main__':
    print("Starting Flask application...")
    print("Current working directory:", os.getcwd())
    print("Looking for .env file...")
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Check if env vars are loaded
    owner_username = os.getenv('OWNER_USERNAME')
    owner_password = os.getenv('OWNER_PASSWORD')
    print(f"OWNER_USERNAME from .env: {owner_username}")
    print(f"OWNER_PASSWORD from .env: {'*' * len(owner_password) if owner_password else 'None'}")
    
    with app.app_context():
        print("Creating database tables...")
        create_tables()
        print("Database tables created!")
        
        conn = get_db()
        cursor = conn.cursor()
        
        print("Checking for owner account...")
        cursor.execute("SELECT user_id, username FROM users WHERE user_role = 'owner'")
        existing_owner = cursor.fetchone()
        
        if existing_owner:
            print(f"Owner account found: {existing_owner['username']}")
        else:
            print("No owner account found. Creating one...")
            
            if not owner_username or not owner_password:
                print("ERROR: OWNER_USERNAME or OWNER_PASSWORD not found in .env!")
                print("Current directory contents:")
                for file in os.listdir('.'):
                    print(f"  - {file}")
                conn.close()
                exit(1)
            
            try:
                # Do NOT hash the username, store it directly
                hashed_password = hash_password(owner_password)
                cursor.execute('''
                    INSERT INTO users (username, password_hash, user_name, user_role, school_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (owner_username, hashed_password, 'System Owner', 'owner', None))
                conn.commit()
                print(f"Owner account '{owner_username}' created successfully!")
            except Exception as e:
                print(f"Error creating owner account: {e}")
                conn.rollback()
        
        conn.close()
    
    print("Starting web server...")
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context=('localhost+1.pem', 'localhost+1-key.pem'))