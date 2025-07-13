"""
AI Model Training for Mobile Security Analysis.

This script trains machine learning models to identify security issues in mobile applications
using the findings from platform-specific security checks.
"""
import os
import json
import logging
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.multioutput import MultiOutputClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MobileSecurityModelTrainer:
    """Trains and manages machine learning models for mobile security analysis."""
    
    def __init__(self, model_dir: str = "models/mobile_security"):
        """Initialize the model trainer.
        
        Args:
            model_dir: Directory to save trained models
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words='english',
            max_df=0.8,
            min_df=2
        )
        
        self.classifier = MultiOutputClassifier(
            RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced'
            )
        )
        
        self.label_binarizer = MultiLabelBinarizer()
        self.model = Pipeline([
            ('vectorizer', self.vectorizer),
            ('classifier', self.classifier)
        ])
        
        # Model metadata
        self.metadata = {
            'created_at': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'features': ['finding_description', 'context'],
            'classes': None,
            'metrics': {}
        }
    
    def prepare_training_data(self, findings: List[Dict[str, Any]]) -> Tuple:
        """Prepare training data from security findings.
        
        Args:
            findings: List of security findings with labels
            
        Returns:
            Tuple of (X, y) for training
        """
        if not findings:
            raise ValueError("No training data provided")
        
        # Extract features and labels
        X = []
        y = []
        
        for finding in findings:
            # Create feature text from finding
            feature_text = f"{finding.get('description', '')} {finding.get('context', '')}"
            X.append(feature_text)
            
            # Extract labels (vulnerability types)
            labels = finding.get('labels', [])
            if not isinstance(labels, list):
                labels = [labels]
            y.append(labels)
        
        # Convert labels to binary matrix
        y_bin = self.label_binarizer.fit_transform(y)
        
        # Save the classes for later use
        self.metadata['classes'] = self.label_binarizer.classes_.tolist()
        
        return X, y_bin
    
    def train(self, X, y, test_size: float = 0.2, random_state: int = 42) -> Dict:
        """Train the model.
        
        Args:
            X: List of text features
            y: Binary label matrix
            test_size: Fraction of data to use for testing
            random_state: Random seed for reproducibility
            
        Returns:
            Dictionary with training metrics
        """
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state
        )
        
        # Train the model
        logger.info("Training model...")
        self.model.fit(X_train, y_train)
        
        # Evaluate the model
        logger.info("Evaluating model...")
        train_metrics = self.evaluate(X_train, y_train, 'train')
        test_metrics = self.evaluate(X_test, y_test, 'test')
        
        # Save metrics
        self.metadata['metrics'] = {
            'train': train_metrics,
            'test': test_metrics
        }
        
        return self.metadata['metrics']
    
    def evaluate(self, X, y_true, dataset_name: str = 'test') -> Dict:
        """Evaluate the model on the given dataset.
        
        Args:
            X: Input features
            y_true: True labels
            dataset_name: Name of the dataset (for logging)
            
        Returns:
            Dictionary with evaluation metrics
        """
        # Make predictions
        y_pred = self.model.predict(X)
        
        # Calculate metrics
        report = classification_report(
            y_true, y_pred,
            target_names=self.label_binarizer.classes_,
            output_dict=True,
            zero_division=0
        )
        
        # Log metrics
        logger.info(f"{dataset_name.upper()} Metrics:")
        for label, metrics in report.items():
            if label in self.label_binarizer.classes_:
                logger.info(f"  {label}: precision={metrics['precision']:.2f}, "
                           f"recall={metrics['recall']:.2f}, f1={metrics['f1-score']:.2f}")
        
        return report
    
    def predict(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Predict vulnerability types for new findings.
        
        Args:
            findings: List of security findings
            
        Returns:
            List of findings with predicted labels and confidence scores
        """
        if not hasattr(self, 'model') or not hasattr(self, 'label_binarizer'):
            raise RuntimeError("Model not trained. Call train() first.")
        
        # Prepare input features
        X = []
        for finding in findings:
            feature_text = f"{finding.get('description', '')} {finding.get('context', '')}"
            X.append(feature_text)
        
        # Make predictions
        probas = self.model.predict_proba(X)
        
        # Process predictions
        results = []
        for i, finding in enumerate(findings):
            result = finding.copy()
            
            # Get predicted labels with probabilities
            predicted_labels = []
            for j, class_name in enumerate(self.label_binarizer.classes_):
                prob = probas[j][i][1]  # Probability of positive class
                if prob > 0.5:  # Threshold can be adjusted
                    predicted_labels.append({
                        'label': class_name,
                        'confidence': float(prob)
                    })
            
            result['predicted_labels'] = predicted_labels
            results.append(result)
        
        return results
    
    def save(self, model_name: str = "mobile_security_model") -> str:
        """Save the trained model and its components.
        
        Args:
            model_name: Base name for the model files
            
        Returns:
            Path to the saved model directory
        """
        # Create model directory
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        model_dir = self.model_dir / f"{model_name}_{timestamp}"
        model_dir.mkdir(parents=True, exist_ok=True)
        
        # Save model components
        model_path = model_dir / "model.joblib"
        joblib.dump(self.model, model_path)
        
        # Save label binarizer
        label_binarizer_path = model_dir / "label_binarizer.joblib"
        joblib.dump(self.label_binarizer, label_binarizer_path)
        
        # Save metadata
        self.metadata['saved_at'] = datetime.utcnow().isoformat()
        metadata_path = model_dir / "metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(self.metadata, f, indent=2)
        
        logger.info(f"Model saved to {model_dir}")
        return str(model_dir)
    
    @classmethod
    def load(cls, model_dir: str) -> 'MobileSecurityModelTrainer':
        """Load a trained model from disk.
        
        Args:
            model_dir: Directory containing the saved model
            
        Returns:
            Loaded MobileSecurityModelTrainer instance
        """
        model_dir = Path(model_dir)
        
        # Initialize a new trainer
        trainer = cls()
        
        # Load model components
        model_path = model_dir / "model.joblib"
        trainer.model = joblib.load(model_path)
        
        # Load label binarizer
        label_binarizer_path = model_dir / "label_binarizer.joblib"
        trainer.label_binarizer = joblib.load(label_binarizer_path)
        
        # Load metadata
        metadata_path = model_dir / "metadata.json"
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                trainer.metadata = json.load(f)
        
        return trainer


def generate_synthetic_data(sample_size: int = 1000) -> List[Dict[str, Any]]:
    """Generate synthetic training data for demonstration.
    
    In a real-world scenario, you would replace this with actual labeled data
    from your security assessments.
    """
    import random
    from faker import Faker
    
    fake = Faker()
    
    # Define vulnerability types and their characteristics
    vuln_types = [
        {
            'name': 'insecure_storage',
            'keywords': ['storage', 'shared_prefs', 'sqlite', 'external', 'sdcard'],
            'contexts': ['SharedPreferences', 'SQLite', 'External Storage', 'Internal Storage']
        },
        {
            'name': 'ssl_issues',
            'keywords': ['ssl', 'tls', 'certificate', 'trustmanager', 'allowsarbitraryloads'],
            'contexts': ['WebView', 'Network', 'URLConnection', 'OkHttp']
        },
        {
            'name': 'hardcoded_secrets',
            'keywords': ['apikey', 'secret', 'password', 'token', 'credentials'],
            'contexts': ['Source Code', 'Strings', 'Gradle', 'Build Config']
        },
        {
            'name': 'insecure_communication',
            'keywords': ['http://', 'cleartext', 'unencrypted', 'smb://', 'ftp://'],
            'contexts': ['Network', 'WebView', 'File Transfer', 'API Calls']
        },
        {
            'name': 'code_tampering',
            'keywords': ['root', 'jailbreak', 'debuggable', 'emulator', 'frida'],
            'contexts': ['Root Detection', 'Debug Detection', 'Anti-Tamper']
        },
        {
            'name': 'insecure_cryptography',
            'keywords': ['md5', 'sha1', 'des', 'ecb', 'rsa/none/nopadding'],
            'contexts': ['Crypto', 'Hashing', 'Encryption', 'Key Generation']
        },
        {
            'name': 'insecure_components',
            'keywords': ['exported', 'intent', 'permission', 'provider', 'broadcast'],
            'contexts': ['Activity', 'Service', 'BroadcastReceiver', 'ContentProvider']
        },
        {
            'name': 'data_leakage',
            'keywords': ['log', 'system.out', 'logcat', 'crashlytics', 'analytics'],
            'contexts': ['Logging', 'Crash Reporting', 'Analytics', 'Third-Party SDKs']
        }
    ]
    
    findings = []
    
    for _ in range(sample_size):
        # Select random vulnerability types (1-3 per finding)
        num_vulns = random.randint(1, 3)
        selected_vulns = random.sample(vuln_types, num_vulns)
        
        # Generate finding text
        description = fake.sentence()
        context = random.choice(selected_vulns[0]['contexts'])
        
        # Add keywords from selected vulnerabilities
        for vuln in selected_vulns:
            if random.random() > 0.3:  # 70% chance to add a keyword
                keyword = random.choice(vuln['keywords'])
                description += f" {keyword}"
        
        # Create finding
        finding = {
            'description': description,
            'context': context,
            'severity': random.choice(['low', 'medium', 'high', 'critical']),
            'labels': [v['name'] for v in selected_vulns]
        }
        
        findings.append(finding)
    
    return findings


def main():
    """Main function for training the model."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Train a mobile security analysis model')
    parser.add_argument('--train-data', type=str, help='Path to training data JSON file')
    parser.add_argument('--output-dir', type=str, default='models/mobile_security',
                       help='Directory to save the trained model')
    parser.add_argument('--test-size', type=float, default=0.2,
                       help='Fraction of data to use for testing')
    parser.add_argument('--synthetic-data', action='store_true',
                       help='Generate synthetic training data')
    parser.add_argument('--synthetic-size', type=int, default=1000,
                       help='Number of synthetic samples to generate')
    
    args = parser.parse_args()
    
    # Initialize trainer
    trainer = MobileSecurityModelTrainer(args.output_dir)
    
    # Load or generate training data
    if args.train_data:
        logger.info(f"Loading training data from {args.train_data}")
        with open(args.train_data, 'r') as f:
            findings = json.load(f)
    elif args.synthetic_data:
        logger.info(f"Generating {args.synthetic_size} synthetic training samples")
        findings = generate_synthetic_data(args.synthetic_size)
        
        # Save synthetic data for reference
        os.makedirs('data/synthetic', exist_ok=True)
        output_file = f'data/synthetic/mobile_security_train_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)
        logger.info(f"Saved synthetic data to {output_file}")
    else:
        raise ValueError("Either --train-data or --synthetic-data must be provided")
    
    # Prepare and train the model
    try:
        X, y = trainer.prepare_training_data(findings)
        metrics = trainer.train(X, y, test_size=args.test_size)
        
        # Save the trained model
        model_dir = trainer.save()
        logger.info(f"Model training complete. Model saved to {model_dir}")
        
        # Print final metrics
        print("\nTraining complete!")
        print(f"Model saved to: {model_dir}")
        print("\nTest Set Metrics:")
        for label, score in metrics['test'].items():
            if isinstance(score, dict) and 'f1-score' in score:
                print(f"  {label}: f1={score['f1-score']:.3f} (precision={score['precision']:.3f}, recall={score['recall']:.3f})")
        
        return 0
    
    except Exception as e:
        logger.error(f"Error during model training: {str(e)}", exc_info=True)
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
