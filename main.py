import os
import io
import base64
import logging
from PIL import Image
from dotenv import load_dotenv
from datetime import datetime
from werkzeug.utils import secure_filename
from wrapper import IntelligentPIIPipeline, Config
from flask import Flask, render_template, request, jsonify, send_file

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['OUTPUT_FOLDER'] = 'output'

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'image': {'png', 'jpg', 'jpeg', 'bmp'},
    'document': {'pdf'},
    'spreadsheet': {'xlsx', 'xls', 'csv'}
}

# Create folders
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize pipeline
config = Config(groq_api_key=os.getenv("GROQ_API_KEY"))
pipeline = IntelligentPIIPipeline(config)

def allowed_file(filename, file_type):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS.get(file_type, set())

def get_file_type(filename):
    """Determine file type from extension"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in ALLOWED_EXTENSIONS['image']:
        return 'image'
    elif ext in ALLOWED_EXTENSIONS['document']:
        return 'document'
    elif ext in ALLOWED_EXTENSIONS['spreadsheet']:
        return 'spreadsheet'
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat():
    """Handle chat messages with PII redaction"""
    try:
        data = request.json
        user_message = data.get('message', '')
        
        if not user_message:
            return jsonify({'error': 'Empty message'}), 400
        
        # Process with PII pipeline
        result = pipeline.process_text(user_message, verbose=False)
        
        # Build response
        response = {
            'success': True,
            'original_message': result['original'],
            'redacted_message': result['anonymized'],
            'llm_response': result['final_response'],
            'llm_response_raw': result['llm_response_anonymized'],
            'redaction_summary': {
                'total_redacted': len(result['redacted_entities']),
                'total_kept': len(result['kept_entities']),
                'redacted_entities': result['redacted_entities'],
                'kept_entities': result['kept_entities'],
                'redaction_report': result['redaction_report']
            }
        }
        
        # Clear pipeline state for next message
        pipeline.pii_guard.clear()
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Chat error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file uploads and process them"""
    try:
        logger.info("Upload endpoint hit")
        logger.info(f"Request files: {request.files}")
        
        if 'file' not in request.files:
            logger.error("No file in request")
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        logger.info(f"File received: {file.filename}")
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Secure filename
        filename = secure_filename(file.filename)
        file_type = get_file_type(filename)
        
        logger.info(f"File type: {file_type}")
        
        if not file_type:
            return jsonify({'error': f'File type not supported. Filename: {filename}'}), 400
        
        # Save uploaded file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        logger.info(f"Saving file to: {filepath}")
        file.save(filepath)
        
        logger.info(f"Processing {file_type}: {filename}")
        
        # Process based on file type
        if file_type == 'image':
            result = process_image_file(filepath, filename)
        elif file_type == 'document':
            result = process_pdf_file(filepath, filename)
        elif file_type == 'spreadsheet':
            result = process_spreadsheet_file(filepath, filename)
        else:
            return jsonify({'error': 'Unsupported file type'}), 400
        
        logger.info("Processing complete")
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Upload error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

def process_image_file(filepath, original_filename):
    """Process image with PII redaction"""
    try:
        logger.info(f"Starting image processing: {filepath}")
        result = pipeline.process_image(filepath)
        
        logger.info("Image processing complete, reading images")
        logger.info(f"Output file: {result['output_file']}")
        
        # Read original and redacted images
        original_img = Image.open(filepath)
        redacted_img = Image.open(result['output_file'])
        
        # Convert to base64 for display
        def img_to_base64(img):
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)
            return base64.b64encode(buffer.read()).decode()
        
        logger.info("Converting images to base64")
        original_b64 = img_to_base64(original_img)
        redacted_b64 = img_to_base64(redacted_img)
        
        # Get redaction summary
        summary = result['redaction_log']['summary']
        detections = result['redaction_log']['detections']
        
        # Get just the filename for download
        output_filename = os.path.basename(result['output_file'])
        
        logger.info(f"Output filename for download: {output_filename}")
        logger.info(f"Returning result with {summary['total_detections']} detections")
        
        return {
            'success': True,
            'file_type': 'image',
            'original_filename': original_filename,
            'original_image': f"data:image/png;base64,{original_b64}",
            'redacted_image': f"data:image/png;base64,{redacted_b64}",
            'download_url': f"/download/{output_filename}",
            'output_path': result['output_file'],  # Store full path for download
            'summary': {
                'total_detections': summary['total_detections'],
                'total_redactions': summary['total_redactions'],
                'by_type': summary['by_type'],
                'by_severity': summary['by_severity'],
                'compliance_notes': summary.get('compliance_notes', [])
            },
            'detections': detections[:10]
        }
    
    except Exception as e:
        logger.error(f"Image processing error: {e}")
        import traceback
        traceback.print_exc()
        raise

def process_pdf_file(filepath, original_filename):
    """Process PDF with PII redaction"""
    try:
        result = pipeline.pdf_handler.process_pdf(filepath)
        
        return {
            'success': True,
            'file_type': 'pdf',
            'original_filename': original_filename,
            'pages': result['pages'],
            'download_url': f"/download/{os.path.basename(result['output_file'])}",
            'summary': {
                'total_redacted': len(result['pii_found']),
                'total_kept': len(result.get('entities_kept', [])),
                'redacted_entities': result['pii_found'],
                'kept_entities': result.get('entities_kept', [])
            }
        }
    
    except Exception as e:
        logger.error(f"PDF processing error: {e}")
        import traceback
        traceback.print_exc()
        raise

def process_spreadsheet_file(filepath, original_filename):
    """Process Excel/CSV with PII redaction"""
    try:
        ext = filepath.rsplit('.', 1)[1].lower()
        
        if ext == 'csv':
            result = pipeline.spreadsheet_handler.process_csv(filepath)
        else:
            result = pipeline.spreadsheet_handler.process_excel(filepath)
        
        stats = result['stats']
        
        return {
            'success': True,
            'file_type': 'spreadsheet',
            'original_filename': original_filename,
            'download_url': f"/download/{os.path.basename(result['output_file'])}",
            'summary': {
                'sheets_processed': stats.get('sheets_processed', 0),
                'rows': stats.get('rows', 0),
                'columns': stats.get('columns', 0),
                'cells_redacted': stats.get('cells_redacted', 0),
                'total_redacted': len(stats.get('pii_found', {})),
                'redacted_entities': stats.get('pii_found', {})
            }
        }
    
    except Exception as e:
        logger.error(f"Spreadsheet processing error: {e}")
        import traceback
        traceback.print_exc()
        raise

@app.route('/download/<path:filename>')
def download_file(filename):
    """Download processed file"""
    try:
        logger.info(f"Download request for: {filename}")
        
        # List of possible locations to check
        possible_paths = [
            filename,  # Current directory (where redacted files are saved)
            os.path.join(app.config['OUTPUT_FOLDER'], filename),
            os.path.join(os.getcwd(), filename),
            os.path.abspath(filename)
        ]
        
        # Try each path
        for filepath in possible_paths:
            logger.info(f"Checking path: {filepath}")
            if os.path.exists(filepath):
                logger.info(f"File found at: {filepath}")
                return send_file(
                    filepath, 
                    as_attachment=True,
                    download_name=filename
                )
        
        # If not found, log all checked paths
        logger.error(f"File not found. Checked paths:")
        for path in possible_paths:
            logger.error(f"  - {path} (exists: {os.path.exists(path)})")
        
        # List files in current directory for debugging
        logger.error(f"Files in current directory: {os.listdir('.')}")
        if os.path.exists(app.config['OUTPUT_FOLDER']):
            logger.error(f"Files in output folder: {os.listdir(app.config['OUTPUT_FOLDER'])}")
        
        return jsonify({'error': 'File not found'}), 404
    
    except Exception as e:
        logger.error(f"Download error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'groq_api_configured': bool(os.getenv("GROQ_API_KEY"))
    })

if __name__ == '__main__':
    # Print all registered routes for debugging
    logger.info("\n" + "="*50)
    logger.info("Registered Routes:")
    logger.info("="*50)
    for rule in app.url_map.iter_rules():
        logger.info(f"{rule.endpoint:30s} {rule.rule:40s} {list(rule.methods)}")
    logger.info("="*50 + "\n")

    app.run(debug=True, host='0.0.0.0', port=5000)  