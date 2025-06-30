# app.py

from flask import Flask, request, render_template, send_file, jsonify
import PyPDF2
import os
from werkzeug.utils import secure_filename
import tempfile
import itertools
import string
import time
import threading
import logging
import uuid
from pathlib import Path
import zipfile
import io

# Image processing imports with error handling
try:
    import fitz  # PyMuPDF for image operations
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False
    print("PyMuPDF not available. Install with: pip install PyMuPDF")

try:
    from pdf2image import convert_from_path, convert_from_bytes
    from pdf2image.exceptions import PDFInfoNotInstalledError, PDFPageCountError, PDFSyntaxError
    PDF2IMAGE_AVAILABLE = True
except ImportError:
    PDF2IMAGE_AVAILABLE = False
    print("pdf2image not available. Install with: pip install pdf2image")

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Pillow not available. Install with: pip install Pillow")

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
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload for multiple images

# Dictionary of common passwords for cracking
COMMON_PASSWORDS = [
    '1234', 'password', 'admin', 'user', '123456', 'qwerty', 'letmein',
    'welcome', '123', 'abc123', 'password1', 'admin123', 'test', '12345',
    'password123', 'admin1', 'root', 'guest', 'demo', 'default'
]

# Supported file formats
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'svg'}
ALLOWED_PDF_EXTENSIONS = {'pdf'}

def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def check_dependencies():
    """Check if required dependencies are available"""
    missing_deps = []
    if not PDF2IMAGE_AVAILABLE:
        missing_deps.append("pdf2image")
    if not PIL_AVAILABLE:
        missing_deps.append("Pillow")
    if not PYMUPDF_AVAILABLE:
        missing_deps.append("PyMuPDF")
    
    return missing_deps

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
                if not allowed_file(original_filename, ALLOWED_PDF_EXTENSIONS):
                    return jsonify({'error': 'Only PDF files are allowed for encryption'}), 400
                if 'password' not in request.form or not request.form['password']:
                    return jsonify({'error': 'Password is required for encryption'}), 400
                password = request.form['password']
                return encrypt_pdf(filepath, password, original_filename)
            
            elif action == 'decrypt':
                if not allowed_file(original_filename, ALLOWED_PDF_EXTENSIONS):
                    return jsonify({'error': 'Only PDF files are allowed for decryption'}), 400
                if 'password' not in request.form or not request.form['password']:
                    return jsonify({'error': 'Password is required for decryption'}), 400
                password = request.form['password']
                return decrypt_pdf(filepath, password, original_filename)
            
            elif action == 'crack':
                if not allowed_file(original_filename, ALLOWED_PDF_EXTENSIONS):
                    return jsonify({'error': 'Only PDF files are allowed for password cracking'}), 400
                return crack_pdf_password(filepath, original_filename)
            
            elif action == 'pdf_to_images':
                if not allowed_file(original_filename, ALLOWED_PDF_EXTENSIONS):
                    return jsonify({'error': 'Only PDF files are allowed for image conversion'}), 400
                
                # Check dependencies
                if not PDF2IMAGE_AVAILABLE:
                    return jsonify({'error': 'pdf2image library not installed. Please install with: pip install pdf2image'}), 400
                
                return convert_pdf_to_images(filepath, original_filename)
            
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

@app.route('/upload_images', methods=['POST'])
def upload_images():
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files uploaded'}), 400
        
        files = request.files.getlist('files')
        
        if not files or all(file.filename == '' for file in files):
            return jsonify({'error': 'No files selected'}), 400
        
        # Check dependencies
        if not PIL_AVAILABLE:
            return jsonify({'error': 'Pillow library not installed. Please install with: pip install Pillow'}), 400
        
        # Validate all files are images
        for file in files:
            if not allowed_file(file.filename, ALLOWED_IMAGE_EXTENSIONS):
                return jsonify({'error': f'File {file.filename} is not a supported image format'}), 400
        
        # Make sure the upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Save all uploaded images
        image_paths = []
        for file in files:
            unique_id = uuid.uuid4().hex[:8]
            unique_filename = f"{unique_id}_{secure_filename(file.filename)}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)
            image_paths.append(filepath)
        
        try:
            return convert_images_to_pdf(image_paths, files[0].filename)
        finally:
            # Clean up uploaded files
            for filepath in image_paths:
                if os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                        logger.info(f"Deleted uploaded file: {filepath}")
                    except Exception as e:
                        logger.error(f"Error deleting file {filepath}: {str(e)}")
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

def convert_images_to_pdf(image_paths, first_filename):
    """Convert multiple images to a single PDF"""
    try:
        logger.info(f"Converting {len(image_paths)} images to PDF")
        
        # Create a list to store processed images
        images = []
        
        for image_path in image_paths:
            # Open and process each image
            img = Image.open(image_path)
            
            # Convert to RGB if necessary (for PNG with transparency, etc.)
            if img.mode != 'RGB':
                # Create a white background for transparent images
                rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                if img.mode in ('RGBA', 'LA'):
                    rgb_img.paste(img, mask=img.split()[-1])
                else:
                    rgb_img.paste(img)
                img = rgb_img
            
            # Optimize image size if too large
            max_size = (2480, 3508)  # A4 size at 300 DPI
            if img.size[0] > max_size[0] or img.size[1] > max_size[1]:
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            images.append(img)
        
        # Create output filename
        file_id = uuid.uuid4().hex[:8]
        base_name = os.path.splitext(first_filename)[0]
        pdf_filename = f"images_to_pdf_{file_id}_{secure_filename(base_name)}.pdf"
        temp_pdf_path = os.path.join(tempfile.gettempdir(), pdf_filename)
        
        # Save as PDF
        if images:
            # Save the first image with additional images appended
            images[0].save(
                temp_pdf_path, 
                "PDF",
                resolution=300.0,
                save_all=True,
                append_images=images[1:] if len(images) > 1 else []
            )
        
        logger.info(f"Successfully converted images to PDF: {pdf_filename}")
        
        return jsonify({
            'status': 'success',
            'pdf_url': f'/download/{pdf_filename}',
            'pdf_filename': f"Images_to_PDF_{base_name}.pdf",
            'image_count': len(image_paths),
            'message': f'Successfully converted {len(image_paths)} images to PDF! Click to download.'
        })
    
    except Exception as e:
        logger.error(f"Error in convert_images_to_pdf: {str(e)}")
        raise

def convert_pdf_to_images(filepath, original_filename):
    """Convert PDF pages to images and return as ZIP"""
    try:
        logger.info(f"Converting PDF to images: {original_filename}")
        
        # Convert PDF to images using pdf2image
        try:
            # Use convert_from_path with high DPI for better quality
            pages = convert_from_path(
                filepath, 
                dpi=300, 
                fmt='JPEG',
                thread_count=1,
                use_pdftocairo=False
            )
        except PDFInfoNotInstalledError:
            return jsonify({'error': 'Poppler utilities not found. Please install poppler for your system.'}), 400
        except PDFPageCountError:
            return jsonify({'error': 'Could not determine the number of pages in the PDF.'}), 400
        except PDFSyntaxError:
            return jsonify({'error': 'PDF syntax error. The file may be corrupted.'}), 400
        except Exception as e:
            logger.error(f"Error converting PDF with pdf2image: {str(e)}")
            return jsonify({'error': 'Error converting PDF to images. Make sure the PDF is not corrupted.'}), 400
        
        if not pages:
            return jsonify({'error': 'No pages found in PDF'}), 400
        
        # Create ZIP file containing all images
        file_id = uuid.uuid4().hex[:8]
        base_name = os.path.splitext(original_filename)[0]
        zip_filename = f"pdf_to_images_{file_id}_{secure_filename(base_name)}.zip"
        temp_zip_path = os.path.join(tempfile.gettempdir(), zip_filename)
        
        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for i, page in enumerate(pages):
                # Save each page as JPEG
                img_bytes = io.BytesIO()
                page.save(img_bytes, format='JPEG', quality=95)
                img_bytes.seek(0)
                
                # Add to ZIP with proper filename
                img_filename = f"{base_name}_page_{i+1:03d}.jpg"
                zipf.writestr(img_filename, img_bytes.getvalue())
        
        logger.info(f"Successfully converted PDF to {len(pages)} images")
        
        return jsonify({
            'status': 'success',
            'download_url': f'/download/{zip_filename}',
            'filename': f"{base_name}_Images.zip",
            'page_count': len(pages),
            'message': f'Successfully converted PDF to {len(pages)} images! Click to download ZIP file.'
        })
    
    except Exception as e:
        logger.error(f"Error in convert_pdf_to_images: {str(e)}")
        raise

def secure_filename(filename):
    """Generate a secure filename"""
    return filename.replace(' ', '_').replace('(', '').replace(')', '')

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
        
        # Determine file location and mimetype
        if filename.endswith('.pdf'):
            file_path = os.path.join(tempfile.gettempdir(), filename)
            mimetype = 'application/pdf'
        elif filename.endswith('.zip'):
            file_path = os.path.join(tempfile.gettempdir(), filename)
            mimetype = 'application/zip'
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
    app.run(host='0.0.0.0', port=port, debug=True)
