'''
pip install Flask-WTF
'''

# app.py
from flask import Flask, request, render_template, send_file, jsonify
import PyPDF2
import os
from werkzeug.utils import secure_filename  # Import added
import tempfile
import itertools
import string
import time
import threading
import logging
import uuid
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Add secret key for production
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secure-secret-key-change-in-production')

UPLOAD_FOLDER = 'uploads'
TEMP_DOWNLOAD_FOLDER = 'temp_downloads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TEMP_DOWNLOAD_FOLDER'] = TEMP_DOWNLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Dictionary of common passwords for cracking
COMMON_PASSWORDS = [
    '1234', 'password', 'admin', 'user', '123456', 'qwerty', 'letmein',
    'welcome', '123', 'abc123', 'password1', 'admin123', 'test'
]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
            
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        if 'action' not in request.form:
            return jsonify({'error': 'No action specified'}), 400
            
        action = request.form['action']
        
        # Make sure the upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Generate unique filename to prevent collisions
        unique_id = uuid.uuid4().hex[:8]
        original_filename = file.filename
        unique_filename = f"{unique_id}_{secure_filename(original_filename)}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Save uploaded file
        file.save(filepath)
        
        try:
            if action == 'encrypt':
                if 'password' not in request.form or not request.form['password']:
                    return jsonify({'error': 'Password is required for encryption'}), 400
                    
                password = request.form['password']
                return encrypt_pdf(filepath, password, original_filename)
                
            elif action == 'decrypt':
                if 'password' not in request.form or not request.form['password']:
                    return jsonify({'error': 'Password is required for decryption'}), 400
                    
                password = request.form['password']
                return decrypt_pdf(filepath, password, original_filename)
                
            elif action == 'crack':
                return crack_pdf_password(filepath, original_filename)
                
            else:
                return jsonify({'error': 'Invalid action specified'}), 400
                
        except PyPDF2.errors.PdfReadError as e:
            logger.error(f"PDF Read Error: {str(e)}")
            return jsonify({'error': f'PDF processing error: {str(e)}'}), 400
            
        except Exception as e:
            logger.error(f"Error processing file: {str(e)}")
            return jsonify({'error': f'Error processing file: {str(e)}'}), 500
            
        finally:
            # Clean up uploaded file
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                    logger.info(f"Deleted uploaded file: {filepath}")
                except Exception as e:
                    logger.error(f"Error deleting file {filepath}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

def secure_filename(filename):
    """Generate a secure filename"""
    return filename.replace(' ', '_')

def encrypt_pdf(filepath, password, original_filename):
    """Encrypt a PDF with password and return download information"""
    try:
        logger.info(f"Encrypting file: {original_filename}")
        
        pdf_file = PyPDF2.PdfReader(filepath)
        pdf_writer = PyPDF2.PdfWriter()
        
        # Add all pages to the writer
        for page in pdf_file.pages:
            pdf_writer.add_page(page)
            
        # Encrypt the PDF
        pdf_writer.encrypt(password)
        
        # Make sure temp download folder exists
        os.makedirs(app.config['TEMP_DOWNLOAD_FOLDER'], exist_ok=True)
        
        # Create a unique name for the encrypted PDF
        file_id = uuid.uuid4().hex[:8]
        encrypted_filename = f"encrypted_{file_id}_{secure_filename(original_filename)}"
        temp_pdf_path = os.path.join(tempfile.gettempdir(), encrypted_filename)
        
        # Write the encrypted PDF
        with open(temp_pdf_path, 'wb') as output_file:
            pdf_writer.write(output_file)
            
        logger.info(f"Successfully encrypted PDF: {original_filename}")
        
        return jsonify({
            'status': 'success',
            'pdf_url': f'/download/{encrypted_filename}',
            'pdf_filename': f"Encrypted_{original_filename}",
            'password': password,
            'message': 'PDF encrypted successfully! Click to download.'
        })
        
    except Exception as e:
        logger.error(f"Error in encrypt_pdf: {str(e)}")
        raise

def decrypt_pdf(filepath, password, original_filename):
    """Decrypt a PDF with password and return download information"""
    try:
        logger.info(f"Decrypting file: {original_filename}")
        
        pdf_file = PyPDF2.PdfReader(filepath)
        
        if not pdf_file.is_encrypted:
            return jsonify({'error': 'This PDF is not encrypted'}), 400
            
        # Try to decrypt with provided password
        if not pdf_file.decrypt(password):
            return jsonify({'error': 'Incorrect password'}), 400
            
        pdf_writer = PyPDF2.PdfWriter()
        
        # Add all pages to the writer
        for page in pdf_file.pages:
            pdf_writer.add_page(page)
            
        # Create a unique name for the decrypted PDF
        file_id = uuid.uuid4().hex[:8]
        decrypted_filename = f"decrypted_{file_id}_{secure_filename(original_filename)}"
        temp_pdf_path = os.path.join(tempfile.gettempdir(), decrypted_filename)
        
        # Write the decrypted PDF
        with open(temp_pdf_path, 'wb') as output_file:
            pdf_writer.write(output_file)
            
        logger.info(f"Successfully decrypted PDF: {original_filename}")
        
        return jsonify({
            'status': 'success',
            'pdf_url': f'/download/{decrypted_filename}',
            'pdf_filename': f"Decrypted_{original_filename}",
            'message': 'PDF decrypted successfully! Click to download.'
        })
        
    except Exception as e:
        logger.error(f"Error in decrypt_pdf: {str(e)}")
        raise

def crack_pdf_password(filepath, original_filename):
    """Attempt to crack PDF password using common passwords and brute force"""
    try:
        logger.info(f"Attempting to crack password for: {original_filename}")
        
        pdf_file = PyPDF2.PdfReader(filepath)
        
        if not pdf_file.is_encrypted:
            return jsonify({'error': 'This PDF is not encrypted'}), 400
            
        # First try common passwords (faster)
        for password in COMMON_PASSWORDS:
            pdf_copy = PyPDF2.PdfReader(filepath)
            if pdf_copy.decrypt(password):
                # Password found, create decrypted PDF
                pdf_writer = PyPDF2.PdfWriter()
                
                for page in pdf_copy.pages:
                    pdf_writer.add_page(page)
                    
                file_id = uuid.uuid4().hex[:8]
                cracked_filename = f"cracked_{file_id}_{secure_filename(original_filename)}"
                temp_pdf_path = os.path.join(tempfile.gettempdir(), cracked_filename)
                
                with open(temp_pdf_path, 'wb') as output_file:
                    pdf_writer.write(output_file)
                    
                logger.info(f"Password cracked: {password}")
                return jsonify({
                    'status': 'success',
                    'pdf_url': f'/download/{cracked_filename}',
                    'cracked_password': password,
                    'pdf_filename': f"Cracked_{original_filename}",
                    'message': f'Password cracked successfully! The password was: {password}'
                })
                
        # Try simple brute force (up to 4 characters)
        characters = string.ascii_lowercase + string.digits
        for length in range(1, 5):
            for attempt in itertools.product(characters, repeat=length):
                password = ''.join(attempt)
                pdf_copy = PyPDF2.PdfReader(filepath)
                if pdf_copy.decrypt(password):
                    # Password found, create decrypted PDF
                    pdf_writer = PyPDF2.PdfWriter()
                    
                    for page in pdf_copy.pages:
                        pdf_writer.add_page(page)
                        
                    file_id = uuid.uuid4().hex[:8]
                    cracked_filename = f"cracked_{file_id}_{secure_filename(original_filename)}"
                    temp_pdf_path = os.path.join(tempfile.gettempdir(), cracked_filename)
                    
                    with open(temp_pdf_path, 'wb') as output_file:
                        pdf_writer.write(output_file)
                        
                    logger.info(f"Password cracked through brute force: {password}")
                    return jsonify({
                        'status': 'success',
                        'pdf_url': f'/download/{cracked_filename}',
                        'cracked_password': password,
                        'pdf_filename': f"Cracked_{original_filename}",
                        'message': f'Password cracked successfully! The password was: {password}'
                    })
                    
        logger.info("Password could not be cracked")
        return jsonify({
            'error': 'Could not crack the password. Try using a correct password with the decrypt option.'
        }), 400
        
    except Exception as e:
        logger.error(f"Error in crack_pdf_password: {str(e)}")
        raise

@app.route('/download/<filename>')
def download_file(filename):
    """Handle file download and cleanup after download"""
    try:
        logger.info(f"Download requested for: {filename}")
        
        # Determine file location based on extension
        if filename.endswith('.pdf'):
            file_path = os.path.join(tempfile.gettempdir(), filename)
            mimetype = 'application/pdf'
        else:
            file_path = os.path.join(app.config['TEMP_DOWNLOAD_FOLDER'], filename)
            mimetype = 'text/plain'
            
        # Use normalized path for cross-platform compatibility
        file_path = os.path.normpath(file_path)
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return jsonify({'error': 'File not found'}), 404
            
        # Prepare download response
        response = send_file(
            file_path,
            as_attachment=True,
            mimetype=mimetype,
            download_name=filename
        )
        
        # Delay deletion to ensure download completes
        def delayed_cleanup(file_path):
            time.sleep(5)  # Wait to ensure download completes
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Successfully deleted {file_path}")
                else:
                    logger.info(f"File not found for deletion: {file_path}")
            except Exception as e:
                logger.error(f"Error deleting file {file_path}: {str(e)}")
                
        # Start cleanup in a separate thread
        threading.Thread(target=delayed_cleanup, args=(file_path,)).start()
        
        return response
        
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({'error': f'Download error: {str(e)}'}), 500

@app.teardown_appcontext
def cleanup(exception):
    """Clean up temporary files on application shutdown"""
    for folder in [UPLOAD_FOLDER, TEMP_DOWNLOAD_FOLDER]:
        if os.path.exists(folder):
            for file in os.listdir(folder):
                try:
                    file_path = os.path.join(folder, file)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        logger.info(f"Cleaned up file: {file_path}")
                except Exception as e:
                    logger.error(f"Error cleaning up file {file}: {str(e)}")

if __name__ == '__main__':
    # Ensure required directories exist
    for folder in [UPLOAD_FOLDER, TEMP_DOWNLOAD_FOLDER]:
        os.makedirs(folder, exist_ok=True)
            
    # Production ready settings - Get port from environment variable
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
