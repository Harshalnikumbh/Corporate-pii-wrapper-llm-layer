import os
import re
import cv2
import fitz
import json
import logging
import openpyxl
import pandas as pd
import requests
import numpy as np
from PIL import Image
from groq import Groq
from datetime import datetime
from dotenv import load_dotenv
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List, Set
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, Pattern, PatternRecognizer

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pii_redaction.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
@dataclass
class Config:
    groq_api_key: str
    groq_model: str = "llama-3.3-70b-versatile"
    spacy_model: str = "en_core_web_trf"
    language: str = "en"
    face_detection_model: str = "haarcascade_frontalface_default.xml"

# Context-Aware Entity Classifier
class ContextAwareClassifier:
    
    def __init__(self, groq_client):
        self.groq_client = groq_client
        self.classification_cache = {}
    
    def classify_entities_in_context(self, text: str, detected_entities: List[Dict]) -> Dict[str, str]:
       
        if not detected_entities:
            return {}
        
        # Build entity list for LLM
        entity_list = []
        for idx, entity in enumerate(detected_entities):
            entity_list.append(f"{idx+1}. '{entity['text']}' (Type: {entity['type']})")
        
        prompt = f"""You are a CORPORATE DATA SECURITY expert analyzing text from a company employee to prevent data leaks.

CONTEXT: This is from a corporate environment. Your job is to protect:
- Employee personal information
- Client/customer data
- Financial information
- Project codes and proprietary information

TEXT TO ANALYZE:
{text}

DETECTED ENTITIES:
{chr(10).join(entity_list)}

CLASSIFY EACH ENTITY INTO ONE CATEGORY:

1. **EMPLOYEE_PII** - Employee's own sensitive information
   - Employee's name (if "my name is X", "I am X")
   - Employee's phone, email, address, ID numbers, salary, bank details
   - Example: "I'm Rahul, my salary is 12 LPA" → EMPLOYEE_PII

2. **CLIENT_SENSITIVE** - Client/customer/vendor information
   - Client names (unless Fortune 500 companies)
   - Customer contact details, addresses
   - Project codes, engagement details
   - Example: "Our client Rajesh from ABC Corp" → CLIENT_SENSITIVE

3. **FINANCIAL_DATA** - Money-related sensitive info
   - Bank accounts, IFSC codes, salary figures
   - Revenue numbers, budgets, invoices
   - Example: "Account: 1234567890" → FINANCIAL_DATA

4. **PUBLIC_FIGURE** - Famous people/large organizations
   - Celebrities, politicians, CEOs of major companies
   - Fortune 500 companies, government organizations
   - Example: "Salman Khan" (actor), "Microsoft", "Google" → PUBLIC_FIGURE

5. **COLLEAGUE_PII** - Other employees/colleagues mentioned
   - Colleague names in context like "my friend X", "my colleague Y"
   - Example: "invite my colleague Amit" → COLLEAGUE_PII

6. **KEEP** - Safe to keep
   - Generic job titles, departments
   - Public companies in professional context
   - Generic locations (cities, countries - not home addresses)

CRITICAL CORPORATE RULES:
- "My name is Salman Khan" → Check if actor or employee (EMPLOYEE_PII if employee)
- "Want to dance with Akshay Kumar" → PUBLIC_FIGURE (famous actor)
- "My friend Amit" → COLLEAGUE_PII (redact)
- Client names (unless huge companies) → CLIENT_SENSITIVE
- ANY bank account, salary, address → Always redact
- Project codes, employee IDs → Always redact
- "Microsoft" in work context → KEEP if discussing company, CLIENT_SENSITIVE if it's your client

Respond ONLY with JSON mapping entity number to classification:
{{"1": "EMPLOYEE_PII", "2": "PUBLIC_FIGURE", "3": "CLIENT_SENSITIVE", ...}}"""

        try:
            response = self.groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=500
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
            if json_match:
                classifications = json.loads(json_match.group())
                
                # Map back to entity texts
                entity_classifications = {}
                for idx, entity in enumerate(detected_entities):
                    classification = classifications.get(str(idx + 1), "KEEP")
                    entity_classifications[entity['text']] = classification
                
                return entity_classifications
            
        except Exception as e:
            logger.warning(f"Context classification failed: {e}")
        
        # Fallback: treat all PERSON entities as potential PII
        return {entity['text']: 'USER_PII' if entity['type'] == 'PERSON' else 'KEEP' 
                for entity in detected_entities}

# Public Entity Verification
class PublicEntityVerifier:
    """Quick verification of public figures using Wikipedia + LLM"""
    
    def __init__(self, groq_client):
        self.groq_client = groq_client
        self.cache = set()
        self.cache_file = "public_entities_cache.json"
        self._load_cache()
    
    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    self.cache = set(data.get('entities', []))
                    logger.info(f"Loaded {len(self.cache)} cached public entities")
            except Exception as e:
                logger.warning(f"Could not load cache: {e}")
    
    def _save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump({'entities': list(self.cache)}, f)
                logger.debug(f"Saved {len(self.cache)} entities to cache")
        except Exception as e:
            logger.warning(f"Could not save cache: {e}")
    
    def is_public_figure(self, name: str) -> bool:
        """Check if entity is a public figure"""
        name_lower = name.lower().strip()
        
        if name_lower in self.cache:
            return True
        
        # Check Wikipedia
        if self._check_wikipedia(name):
            self.cache.add(name_lower)
            self._save_cache()
            logger.info(f"Verified public figure via Wikipedia: {name}")
            return True
        
        # LLM verification
        if self._check_with_llm(name):
            self.cache.add(name_lower)
            self._save_cache()
            logger.info(f"Verified public figure via LLM: {name}")
            return True
        
        logger.debug(f"Not a public figure: {name}")
        return False
    
    def _check_wikipedia(self, name: str) -> bool:
        try:
            url = "https://en.wikipedia.org/w/api.php"
            params = {
                'action': 'query',
                'format': 'json',
                'titles': name,
                'redirects': 1
            }
            response = requests.get(url, params=params, timeout=3)
            data = response.json()
            pages = data.get('query', {}).get('pages', {})
            
            for page_id in pages:
                if page_id != '-1' and 'missing' not in pages[page_id]:
                    return True
            return False
        except Exception as e:
            logger.debug(f"Wikipedia check failed for {name}: {e}")
            return False
    
    def _check_with_llm(self, name: str) -> bool:
        try:
            prompt = f"""Is "{name}" a well-known public figure, celebrity, politician, historical figure, or major organization?

Answer ONLY: YES or NO

Entity: "{name}"
Answer:"""
            
            response = self.groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=10
            )
            
            answer = response.choices[0].message.content.strip().upper()
            return answer.startswith("YES")
        except Exception as e:
            logger.debug(f"LLM verification failed for {name}: {e}")
            return False

# Indian Context PII Recognizers
class IndianPIIRecognizers:
    
    @staticmethod
    def create_aadhaar_recognizer():
        patterns = [
            Pattern("Aadhaar", r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", 0.9),
            Pattern("Aadhaar", r"\b\d{12}\b", 0.85),
        ]
        return PatternRecognizer(
            supported_entity="AADHAAR_NUMBER",
            patterns=patterns,
            context=["aadhaar", "uid", "आधार", "aadhar"]
        )
    
    @staticmethod
    def create_pan_recognizer():
        patterns = [
            Pattern("PAN", r"\b[A-Z]{5}\d{4}[A-Z]\b", 0.95),
        ]
        return PatternRecognizer(
            supported_entity="PAN_NUMBER",
            patterns=patterns,
            context=["pan", "permanent account"]
        )
    
    @staticmethod
    def create_indian_phone_recognizer():
        patterns = [
            Pattern("Indian Phone", r"\b(?:\+91|91)?[\s-]?[6-9]\d{9}\b", 0.9),
        ]
        return PatternRecognizer(
            supported_entity="INDIAN_PHONE",
            patterns=patterns,
            context=["phone", "mobile", "contact", "whatsapp", "call"]
        )
    
    @staticmethod
    def create_indian_pincode_recognizer():
        patterns = [
            Pattern("PIN Code", r"\b[1-9]\d{5}\b", 0.7),
        ]
        return PatternRecognizer(
            supported_entity="PIN_CODE",
            patterns=patterns,
            context=["pincode", "pin", "postal", "zip"]
        )
class CorporatePIIRecognizers:
    """Corporate-specific PII patterns"""
    
    @staticmethod
    def create_bank_account_recognizer():
        patterns = [
            Pattern("Bank Account", r"\b\d{9,18}\b", 0.75),  # Indian accounts
            Pattern("IFSC", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", 0.95),  # IFSC codes
            Pattern("SWIFT", r"\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b", 0.9),  # SWIFT codes
        ]
        return PatternRecognizer(
            supported_entity="BANK_ACCOUNT",
            patterns=patterns,
            context=["account", "bank", "ifsc", "swift", "a/c", "account number"]
        )
    
    @staticmethod
    def create_employee_id_recognizer():
        patterns = [
            Pattern("Employee ID", r"\bEMP[-_]?\d{4,8}\b", 0.9),
            Pattern("Employee ID", r"\b[A-Z]{2,4}\d{4,6}\b", 0.7),  # Generic EMP123456
            Pattern("Employee ID", r"\bSTAFF[-_]?\d{4,8}\b", 0.85),
        ]
        return PatternRecognizer(
            supported_entity="EMPLOYEE_ID",
            patterns=patterns,
            context=["employee", "emp", "staff", "id", "badge"]
        )
    
    @staticmethod
    def create_salary_recognizer():
        patterns = [
            Pattern("Salary", r"\b(?:Rs\.?|INR|₹)\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?\b", 0.85),
            Pattern("Salary", r"\b\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s*(?:LPA|CTC|per annum)\b", 0.9),
        ]
        return PatternRecognizer(
            supported_entity="SALARY_INFO",
            patterns=patterns,
            context=["salary", "ctc", "compensation", "package", "pay"]
        )
    
    @staticmethod
    def create_passport_recognizer():
        patterns = [
            Pattern("Passport", r"\b[A-Z]\d{7}\b", 0.9),  # Indian
            Pattern("Passport", r"\b[A-Z]{1,2}\d{6,9}\b", 0.8),  # International
        ]
        return PatternRecognizer(
            supported_entity="PASSPORT",
            patterns=patterns,
            context=["passport", "travel document"]
        )
    
    @staticmethod
    def create_project_code_recognizer():
        patterns = [
            Pattern("Project Code", r"\bPROJ[-_]?[A-Z0-9]{4,10}\b", 0.85),
            Pattern("Project Code", r"\b[A-Z]{2,4}[-_]\d{3,6}\b", 0.7),
        ]
        return PatternRecognizer(
            supported_entity="PROJECT_CODE",
            patterns=patterns,
            context=["project", "proj", "code", "engagement"]
        )
    
    @staticmethod
    def create_home_address_recognizer():
        # More sophisticated - catches multi-line addresses
        patterns = [
            Pattern("Address", r"\b\d{1,5}\s+[\w\s]{3,50},\s*[\w\s]{3,30},\s*[A-Z]{2}\s+\d{5,6}\b", 0.8),
            Pattern("Address", r"(?i)\b(?:flat|plot|house|bldg|building)\s*(?:no\.?|#)?\s*\d+.*?\d{6}\b", 0.75),
        ]
        return PatternRecognizer(
            supported_entity="HOME_ADDRESS",
            patterns=patterns,
            context=["address", "residence", "home", "street", "apartment"]
        )
    
    @staticmethod
    def create_client_name_recognizer():
        # This will need LLM assistance
        patterns = [
            Pattern("Client", r"\bclient\s+(?:name|code):\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)", 0.7),
        ]
        return PatternRecognizer(
            supported_entity="CLIENT_INFO",
            patterns=patterns,
            context=["client", "customer", "vendor", "partner"]
        )

# Enhanced Context-Aware PII Guard
class ContextAwarePIIGuard:
    
    def __init__(self, spacy_model: str, language: str, groq_client):
        # Initialize Presidio
        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": language, "model_name": spacy_model}]
        }
        provider = NlpEngineProvider(nlp_configuration=nlp_config)
        nlp_engine = provider.create_engine()
        
        # Custom registry with Indian recognizers
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()

        # Add Indian PII recognizers
        registry.add_recognizer(IndianPIIRecognizers.create_aadhaar_recognizer())
        registry.add_recognizer(IndianPIIRecognizers.create_pan_recognizer())
        registry.add_recognizer(IndianPIIRecognizers.create_indian_phone_recognizer())
        registry.add_recognizer(IndianPIIRecognizers.create_indian_pincode_recognizer())

        # Corporate PII
        registry.add_recognizer(CorporatePIIRecognizers.create_bank_account_recognizer())
        registry.add_recognizer(CorporatePIIRecognizers.create_employee_id_recognizer())
        registry.add_recognizer(CorporatePIIRecognizers.create_salary_recognizer())
        registry.add_recognizer(CorporatePIIRecognizers.create_passport_recognizer())
        registry.add_recognizer(CorporatePIIRecognizers.create_project_code_recognizer())
        registry.add_recognizer(CorporatePIIRecognizers.create_home_address_recognizer())
        registry.add_recognizer(CorporatePIIRecognizers.create_client_name_recognizer())
        
        self.analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=[language],
            registry=registry
        )
        self.anonymizer = AnonymizerEngine()
        self.language = language
        
        # Context understanding
        self.context_classifier = ContextAwareClassifier(groq_client)
        self.public_verifier = PublicEntityVerifier(groq_client)
        
        self.mapping = {}
        self.reverse_mapping = {}
        self.kept_entities = set()

        self.redaction_summary = {
        'EMPLOYEE_PII': [],
        'CLIENT_SENSITIVE': [],
        'FINANCIAL_DATA': [],
        'COLLEAGUE_PII': [],
        'BANK_ACCOUNT': [],
        'SALARY_INFO': [],
        'EMPLOYEE_ID': [],
        'PROJECT_CODE': [],
        'HOME_ADDRESS': [],
        'PASSPORT': []
    }
        
    def get_redaction_report(self) -> Dict:
        """Generate detailed redaction report"""
        total_redacted = sum(len(v) for v in self.redaction_summary.values())
        
        report = {
            'total_entities_redacted': total_redacted,
            'total_entities_kept': len(self.kept_entities),
            'redacted_by_category': {},
            'kept_entities_list': list(self.kept_entities),
            'detailed_redactions': self.redaction_summary
        }
        
        # Count by category
        for category, items in self.redaction_summary.items():
            if items:
                report['redacted_by_category'][category] = len(items)
        
        return report

    def anonymize(self, text: str, context_aware: bool = True) -> str:
        """
        Anonymize text with context awareness.
        Only redacts USER_PII and THIRD_PARTY_PII, keeps PUBLIC_FIGURE mentions.
        """
        self.mapping.clear()
        self.reverse_mapping.clear()
        self.kept_entities.clear()
        
        # Detect all PII
        results = self.analyzer.analyze(text=text, language=self.language)
        
        if not results:
            return text
        
        # Build entity list for classification
        detected_entities = []
        for result in results:
            entity_text = text[result.start:result.end]
            detected_entities.append({
                'text': entity_text,
                'type': result.entity_type,
                'start': result.start,
                'end': result.end,
                'score': result.score
            })
        
        # Classify entities based on context
        if context_aware:
            classifications = self.context_classifier.classify_entities_in_context(text, detected_entities)
        else:
            classifications = {e['text']: 'USER_PII' for e in detected_entities}
        
        # Filter results based on classification
        filtered_results = []
        for result in results:
            entity_text = text[result.start:result.end]
            classification = classifications.get(entity_text, 'KEEP')
            
            # Keep public figures and entities marked as KEEP
            if classification in ['PUBLIC_FIGURE', 'KEEP']:
                self.kept_entities.add(entity_text)
                logger.info(f"KEEPING: {entity_text} - {classification}")
                continue
            
            # Redact USER_PII and THIRD_PARTY_PII
            if classification in ['USER_PII', 'THIRD_PARTY_PII', 'EMPLOYEE_PII', 
                      'CLIENT_SENSITIVE', 'FINANCIAL_DATA', 'COLLEAGUE_PII']:
                logger.info(f"REDACTING: {entity_text} - {classification}")
                filtered_results.append(result)

                category = classification if classification in self.redaction_summary else result.entity_type
                if category in self.redaction_summary:
                    self.redaction_summary[category].append({
                        'text': entity_text,
                        'type': result.entity_type,
                        'reason': classification
                    })
        
        if not filtered_results:
            return text
        
        # Anonymize filtered results
        operators = {}
        counters = {}
        
        for result in filtered_results:
            entity_type = result.entity_type
            counters[entity_type] = counters.get(entity_type, 0) + 1
            placeholder = f"<{entity_type}_{counters[entity_type]}>"
            operators[entity_type] = OperatorConfig("replace", {"new_value": placeholder})
        
        anonymized_result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=filtered_results,
            operators=operators
        )
        
        self._build_mapping(text, anonymized_result.text, filtered_results)
        
        return anonymized_result.text
    
    def _build_mapping(self, original: str, anonymized: str, results):
        for result in results:
            original_value = original[result.start:result.end]
            pattern = f"<{result.entity_type}_\\d+>"
            matches = list(re.finditer(pattern, anonymized))
            
            for match in matches:
                placeholder = match.group()
                if placeholder not in self.reverse_mapping:
                    self.reverse_mapping[placeholder] = original_value
                    self.mapping[original_value] = placeholder
                    break
    
    def deanonymize(self, text: str) -> str:
        result = text
        for placeholder, original_value in self.reverse_mapping.items():
            result = result.replace(placeholder, original_value)
            bracket_placeholder = placeholder.replace('<', '[').replace('>', ']')
            result = result.replace(bracket_placeholder, original_value)
            plain_placeholder = placeholder.strip('<>')
            result = re.sub(r'\b' + re.escape(plain_placeholder) + r'\b', original_value, result)
        return result
    
    def clear(self):
        self.mapping.clear()
        self.reverse_mapping.clear()
        self.kept_entities.clear()

        # Clear redaction summary for next run
        for category in self.redaction_summary:
            self.redaction_summary[category].clear()

# Excel/CSV Handler
class SpreadsheetHandler:
    
    def __init__(self, pii_guard: ContextAwarePIIGuard):
        self.pii_guard = pii_guard
    
    def process_excel(self, file_path: str, output_path: str = None) -> Dict:
        """Process Excel file and redact PII"""
        logger.info(f"Processing Excel file: {file_path}")
        
        if not output_path:
            output_path = file_path.replace('.xlsx', '_REDACTED.xlsx').replace('.xls', '_REDACTED.xls')
        
        # Read Excel
        workbook = openpyxl.load_workbook(file_path)
        stats = {
            'sheets_processed': 0,
            'cells_redacted': 0,
            'pii_found': {}
        }
        
        for sheet_name in workbook.sheetnames:
            sheet = workbook[sheet_name]
            stats['sheets_processed'] += 1
            
            for row in sheet.iter_rows():
                for cell in row:
                    if cell.value and isinstance(cell.value, str):
                        original = cell.value
                        anonymized = self.pii_guard.anonymize(original)
                        
                        if original != anonymized:
                            cell.value = anonymized
                            stats['cells_redacted'] += 1
        
        # Save redacted workbook
        workbook.save(output_path)
        logger.info(f"Saved redacted Excel: {output_path}")
        
        stats['pii_found'] = dict(self.pii_guard.reverse_mapping)
        return {
            'type': 'excel',
            'input_file': file_path,
            'output_file': output_path,
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        }
    
    def process_csv(self, file_path: str, output_path: str = None) -> Dict:
        """Process CSV file and redact PII"""
        logger.info(f"Processing CSV file: {file_path}")
        
        if not output_path:
            output_path = file_path.replace('.csv', '_REDACTED.csv')
        
        df = pd.read_csv(file_path)
        original_shape = df.shape
        cells_redacted = 0
        
        for col in df.columns:
            if df[col].dtype == 'object':  # Text columns
                for idx in df.index:
                    if pd.notna(df.at[idx, col]):
                        original = str(df.at[idx, col])
                        anonymized = self.pii_guard.anonymize(original)
                        
                        if original != anonymized:
                            df.at[idx, col] = anonymized
                            cells_redacted += 1
        
        df.to_csv(output_path, index=False)
        logger.info(f"Saved redacted CSV: {output_path}")
        
        return {
            'type': 'csv',
            'input_file': file_path,
            'output_file': output_path,
            'stats': {
                'rows': original_shape[0],
                'columns': original_shape[1],
                'cells_redacted': cells_redacted,
                'pii_found': dict(self.pii_guard.reverse_mapping)
            },
            'timestamp': datetime.now().isoformat()
        }

# Face Redaction
class AdvancedImageRedactor:
    """Redact faces, text (PII), and logos in images"""
    
    def __init__(self, pii_guard: 'ContextAwarePIIGuard' = None):
        self.face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        )
        self.pii_guard = pii_guard
        try:
            import easyocr
            self.ocr_reader = easyocr.Reader(['en'])
            self.ocr_available = True
        except:
            logger.warning("EasyOCR not available. Install: pip install easyocr")
            self.ocr_available = False
    
    def redact_image(self, image: Image.Image, redact_faces=True, 
                     redact_text=True, redact_logos=True) -> Tuple[Image.Image, Dict]:
        """Comprehensive image redaction"""
        img_cv = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        stats = {'faces': 0, 'text_regions': 0, 'logos': 0}
        
        # 1. Redact faces
        if redact_faces:
            img_cv, faces_count = self._redact_faces(img_cv)
            stats['faces'] = faces_count
        
        # 2. Redact text containing PII
        if redact_text and self.ocr_available and self.pii_guard:
            img_cv, text_count = self._redact_text_pii(img_cv)
            stats['text_regions'] = text_count
        
        # 3. Redact logos (template matching or simple color-based)
        if redact_logos:
            img_cv, logo_count = self._redact_logos(img_cv)
            stats['logos'] = logo_count
        
        img_rgb = cv2.cvtColor(img_cv, cv2.COLOR_BGR2RGB)
        return Image.fromarray(img_rgb), stats
    
    def _redact_faces(self, img_cv, blur_level=51):
        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        faces = self.face_cascade.detectMultiScale(
            gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30)
        )
        
        for (x, y, w, h) in faces:
            face_region = img_cv[y:y+h, x:x+w]
            blurred = cv2.GaussianBlur(face_region, (blur_level, blur_level), 30)
            img_cv[y:y+h, x:x+w] = blurred
        
        return img_cv, len(faces)
    
    def _redact_text_pii(self, img_cv):
        """Use OCR to find and redact text containing PII"""
        if not self.ocr_available:
            return img_cv, 0
        
        # Run OCR
        results = self.ocr_reader.readtext(img_cv)
        redacted_count = 0
        
        for (bbox, text, confidence) in results:
            if confidence < 0.3:  # Skip low confidence
                continue
            
            # Check if text contains PII
            anonymized = self.pii_guard.anonymize(text, context_aware=False)
            
            if text != anonymized:  # PII found
                # Get bounding box coordinates
                top_left = tuple(map(int, bbox[0]))
                bottom_right = tuple(map(int, bbox[2]))
                
                # Black out the region
                cv2.rectangle(img_cv, top_left, bottom_right, (0, 0, 0), -1)
                redacted_count += 1
                logger.info(f"Redacted text in image: {text[:20]}... ->  {anonymized[:20]}...")
        
        return img_cv, redacted_count
    
    def _redact_logos(self, img_cv):
        """Simple logo detection using color clustering"""
        # Convert to HSV for better color detection
        hsv = cv2.cvtColor(img_cv, cv2.COLOR_BGR2HSV)
        
        # Define color ranges for common logo colors (you can expand this)
        logo_regions = []
        
        # Example: Detect bright/saturated regions (logos are often colorful)
        mask = cv2.inRange(hsv, (0, 100, 100), (180, 255, 255))
        
        # Find contours
        contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        logo_count = 0
        for contour in contours:
            area = cv2.contourArea(contour)
            # Filter by size (logos are usually 50x50 to 300x300 pixels)
            if 2500 < area < 90000:
                x, y, w, h = cv2.boundingRect(contour)
                # Blur the region
                logo_region = img_cv[y:y+h, x:x+w]
                blurred = cv2.GaussianBlur(logo_region, (99, 99), 30)
                img_cv[y:y+h, x:x+w] = blurred
                logo_count += 1
        
        return img_cv, logo_count

# PDF Handler
class PDFHandler:
    
    def __init__(self, pii_guard: ContextAwarePIIGuard):
        self.pii_guard = pii_guard
    
    def process_pdf(self, input_path: str, output_path: str = None) -> Dict:
        """Extract text, anonymize, and create redacted PDF"""
        if not output_path:
            output_path = input_path.replace('.pdf', '_REDACTED.pdf')
        
        doc = fitz.open(input_path)
        full_text = ""
        anonymized_text = ""
        
        for page in doc:
            text = page.get_text()
            full_text += text
            anonymized = self.pii_guard.anonymize(text)
            anonymized_text += anonymized
        
        # Create redacted PDF
        doc_redact = fitz.open(input_path)
        for page in doc_redact:
            text = page.get_text()
            results = self.pii_guard.analyzer.analyze(text=text, language=self.pii_guard.language)
            
            for result in results:
                entity_text = text[result.start:result.end]
                if entity_text not in self.pii_guard.kept_entities:
                    instances = page.search_for(entity_text)
                    for inst in instances:
                        page.add_redact_annot(inst, fill=(0, 0, 0))
            
            page.apply_redactions()
        
        doc_redact.save(output_path)
        doc_redact.close()
        doc.close()
        
        logger.info(f"Saved redacted PDF: {output_path}")
        
        return {
            'type': 'pdf',
            'input_file': input_path,
            'output_file': output_path,
            'pages': len(doc),
            'pii_found': dict(self.pii_guard.reverse_mapping),
            'entities_kept': list(self.pii_guard.kept_entities),
            'timestamp': datetime.now().isoformat()
        }

# LLM Client
class GroqClient:
    
    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.client = Groq(api_key=api_key)
        self.model = model
    
    def generate(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=1024
        )
        return response.choices[0].message.content

# Main Pipeline
class IntelligentPIIPipeline:
    
    def __init__(self, config: Config):
        self.llm_client = GroqClient(config.groq_api_key, config.groq_model)
        self.pii_guard = ContextAwarePIIGuard(
            spacy_model=config.spacy_model,
            language=config.language,
            groq_client=self.llm_client.client
        )
        self.pdf_handler = PDFHandler(self.pii_guard)
        self.spreadsheet_handler = SpreadsheetHandler(self.pii_guard)
        self.image_redactor = AdvancedImageRedactor(self.pii_guard)
    
    def process_text(self, text: str, verbose: bool = True) -> Dict:
        """Process text with context-aware redaction"""
        try:
            if verbose:
                logger.info("="*80)
                logger.info("PROCESSING TEXT WITH CONTEXT AWARENESS")
                logger.info("="*80)
            
            anonymized = self.pii_guard.anonymize(text, context_aware=True)
            
            if verbose:
                logger.info("Generating LLM response...")
            
            llm_response = self.llm_client.generate(anonymized)
            final_response = self.pii_guard.deanonymize(llm_response)
            
            result = {
                'type': 'text',
                'original': text,
                'anonymized': anonymized,
                'llm_response_anonymized': llm_response,
                'final_response': final_response,
                'redacted_entities': dict(self.pii_guard.reverse_mapping),
                'kept_entities': list(self.pii_guard.kept_entities),
                'redaction_report': self.pii_guard.get_redaction_report(),
                'timestamp': datetime.now().isoformat()
            }
            
            if verbose:
                logger.info("="*80)
                logger.info("RESULTS")
                logger.info("="*80)
                logger.info(f"ORIGINAL: {text}")
                logger.info(f"ANONYMIZED: {anonymized}")
                logger.info(f"RESPONSE: {final_response}")
                logger.info(f"REDACTED: {len(self.pii_guard.reverse_mapping)} entities")
                logger.info(f"KEPT: {len(self.pii_guard.kept_entities)} public figures")
            
            return result
            
        finally:
            self.pii_guard.clear()
    
    def process_file(self, file_path: str) -> Dict:
        """Process any supported file type"""
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == '.pdf':
            return self.pdf_handler.process_pdf(file_path)
        elif ext in ['.xlsx', '.xls']:
            return self.spreadsheet_handler.process_excel(file_path)
        elif ext == '.csv':
            return self.spreadsheet_handler.process_csv(file_path)
        elif ext in ['.jpg', '.jpeg', '.png', '.bmp']:
            return self.process_image(file_path)
        else:
            return {'error': f'Unsupported file type: {ext}'}
    
    def process_image(self, image_path: str) -> Dict:
        """Redact faces, PII text, and logos in image"""
        logger.info(f"Processing image: {image_path}")
        image = Image.open(image_path)
        
        redacted, stats = self.image_redactor.redact_image(
            image, 
            redact_faces=True, 
            redact_text=True, 
            redact_logos=True
        )
        
        output_path = image_path.replace('.', '_REDACTED.')
        redacted.save(output_path)
        
        logger.info(f"Saved redacted image: {output_path}")
        logger.info(f"Stats: {stats['faces']} faces, {stats['text_regions']} text regions, {stats['logos']} logos")
        
        return {
            'type': 'image',
            'input_file': image_path,
            'output_file': output_path,
            'redaction_stats': stats,
            'timestamp': datetime.now().isoformat()
        }

# Save results
def save_results(data: Dict, output_dir: str = "output"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"result_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Saved results to: {filepath}")
    return filepath

# Main CLI
def main():
    config = Config(groq_api_key=os.getenv("GROQ_API_KEY"))
    
    if not config.groq_api_key:
        logger.error("GROQ_API_KEY not set in environment!")
        logger.error("Set it using: export GROQ_API_KEY='your-key'")
        return
    
    pipeline = IntelligentPIIPipeline(config)
    
    logger.info("="*80)
    logger.info("INTELLIGENT CONTEXT-AWARE PII REDACTION SYSTEM")
    logger.info("="*80)
    logger.info("\nFeatures:")
    logger.info("✓ Understands context (user PII vs public figures)")
    logger.info("✓ Supports: Text, PDF, Excel, CSV, Images")
    logger.info("✓ LLM-powered entity classification")
    logger.info("="*80)
    
    while True:
        print("\n\nOptions:")
        print("1. Process text input")
        print("2. Process file (PDF/Excel/CSV/Image)")
        print("3. Batch process directory")
        print("4. Exit")
        
        choice = input("\nChoice: ").strip()
        
        if choice == '1':
            text = input("\nEnter text: ").strip()
            if text:
                result = pipeline.process_text(text, verbose=True)
                save_results(result)
        
        elif choice == '2':
            file_path = input("\nFile path: ").strip()
            if os.path.exists(file_path):
                result = pipeline.process_file(file_path)
                save_results(result)
                logger.info(f"✓ Processed: {file_path}")
            else:
                logger.error("File not found")
        
        elif choice == '3':
            dir_path = input("\nDirectory path: ").strip()
            if os.path.isdir(dir_path):
                files = [f for f in os.listdir(dir_path) 
                        if os.path.splitext(f)[1].lower() in 
                        ['.pdf', '.xlsx', '.xls', '.csv', '.jpg', '.png']]
                
                logger.info(f"Found {len(files)} files to process")
                for file in files:
                    file_path = os.path.join(dir_path, file)
                    logger.info(f"Processing: {file}")
                    result = pipeline.process_file(file_path)
                    save_results(result)
                
                logger.info(f"✓ Batch complete: {len(files)} files processed")
            else:
                logger.error("Directory not found")
        
        elif choice == '4':
            logger.info("Exiting...")
            break

if __name__ == "__main__":
    main()