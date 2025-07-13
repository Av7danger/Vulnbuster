#!/usr/bin/env python3
"""
AI Model Training Script for Mobile Security Analysis.

This script trains machine learning models to detect security issues in mobile applications
using a dataset of known security findings.
"""
import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

import pandas as pd
from sklearn.model_selection import train_test_split

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modes.mobile.ai_model_trainer import (
    AIModelTrainer,
    train_severity_classifier
)
from modes.mobile.models import Finding, Severity

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_training_data(data_path: str) -> List[Dict[str, Any]]:
    """Load training data from a JSON file.
    
    Args:
        data_path: Path to the training data JSON file
        
    Returns:
        List of training examples
    """
    try:
        with open(data_path) as f:
            data = json.load(f)
        
        # Validate the data format
        required_fields = {'title', 'description', 'severity'}
        for i, item in enumerate(data):
            if not all(field in item for field in required_fields):
                logger.warning(f"Missing required fields in item {i}")
                continue
                
            # Ensure severity is valid
            severity = item['severity'].upper()
            if severity not in Severity._member_names_:
                logger.warning(f"Invalid severity '{severity}' in item {i}")
                continue
                
            item['severity'] = severity.lower()
            
        return data
        
    except Exception as e:
        logger.error(f"Failed to load training data: {str(e)}")
        raise

def generate_synthetic_data() -> List[Dict[str, Any]]:
    """Generate synthetic training data for demonstration purposes.
    
    In a real-world scenario, you would use a dataset of real security findings.
    """
    return [
        {
            'title': 'Insecure HTTP Traffic',
            'description': 'Application sends sensitive data over unencrypted HTTP',
            'severity': 'high',
            'details': {
                'url': 'http://example.com/api/login',
                'method': 'POST',
                'sensitive_parameters': ['username', 'password']
            }
        },
        {
            'title': 'Insecure Data Storage',
            'description': 'Sensitive data stored in SharedPreferences without encryption',
            'severity': 'high',
            'details': {
                'storage_type': 'SharedPreferences',
                'key': 'user_credentials',
                'value_preview': '{"username":"admin","password":"s3cr3t"}'
            }
        },
        {
            'title': 'Missing SSL Pinning',
            'description': 'Application does not implement SSL pinning',
            'severity': 'medium',
            'details': {
                'vulnerability': 'CWE-295',
                'impact': 'Man-in-the-middle attacks'
            }
        },
        {
            'title': 'Insecure Logging',
            'description': 'Sensitive information logged to system logs',
            'severity': 'medium',
            'details': {
                'log_level': 'DEBUG',
                'sensitive_data': 'API_KEY=abc123',
                'source': 'com.example.app.ApiClient'
            }
        },
        {
            'title': 'Weak Cryptography',
            'description': 'Application uses deprecated cryptographic algorithm',
            'severity': 'high',
            'details': {
                'algorithm': 'MD5',
                'usage': 'Password hashing',
                'recommendation': 'Use bcrypt or Argon2'
            }
        },
        {
            'title': 'Insecure Broadcast Receiver',
            'description': 'Broadcast receiver is exported and not protected by permissions',
            'severity': 'medium',
            'details': {
                'component': 'com.example.app.MyReceiver',
                'exported': True,
                'permission': None
            }
        },
        {
            'title': 'Insecure WebView Implementation',
            'description': 'WebView allows JavaScript execution from untrusted sources',
            'severity': 'high',
            'details': {
                'vulnerability': 'CWE-79',
                'impact': 'Cross-Site Scripting (XSS)'
            }
        },
        {
            'title': 'Insecure Random Number Generation',
            'description': 'Application uses insecure random number generator',
            'severity': 'medium',
            'details': {
                'class': 'java.util.Random',
                'recommendation': 'Use java.security.SecureRandom'
            }
        },
        {
            'title': 'Hardcoded API Key',
            'description': 'Sensitive API key found in source code',
            'severity': 'high',
            'details': {
                'key': 'AIzaSyD...',
                'location': 'res/values/strings.xml',
                'recommendation': 'Store keys securely using Android Keystore System'
            }
        },
        {
            'title': 'Insecure Content Provider',
            'description': 'Content provider is exported and does not require permissions',
            'severity': 'high',
            'details': {
                'authority': 'com.example.app.provider',
                'exported': True,
                'permission': None
            }
        }
    ]

def train_model(
    training_data: List[Dict[str, Any]],
    output_dir: str,
    test_size: float = 0.2,
    random_state: int = 42
) -> Dict[str, Any]:
    """Train the AI model and save it to disk.
    
    Args:
        training_data: List of training examples
        output_dir: Directory to save the trained model
        test_size: Proportion of data to use for testing
        random_state: Random seed for reproducibility
        
    Returns:
        Dictionary containing training results
    """
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Convert to DataFrame for easier manipulation
    df = pd.DataFrame(training_data)
    
    # Split data into training and test sets
    train_data, test_data = train_test_split(
        df, test_size=test_size, random_state=random_state, stratify=df['severity']
    )
    
    logger.info(f"Training set size: {len(train_data)}")
    logger.info(f"Test set size: {len(test_data)}")
    
    # Convert back to list of dicts for the trainer
    train_data_list = train_data.to_dict('records')
    test_data_list = test_data.to_dict('records')
    
    # Train the model
    trainer = train_severity_classifier(train_data_list, output_dir=str(output_path))
    
    # Evaluate on test set
    test_predictions = []
    for item in test_data_list:
        try:
            predicted_severity = trainer.predict_severity(item)
            test_predictions.append({
                'actual': item['severity'],
                'predicted': predicted_severity,
                'title': item['title'],
                'description': item['description']
            })
        except Exception as e:
            logger.warning(f"Error predicting severity for item: {str(e)}")
    
    # Calculate accuracy
    correct = sum(1 for p in test_predictions if p['actual'] == p['predicted'])
    accuracy = correct / len(test_predictions) if test_predictions else 0
    
    logger.info(f"Test accuracy: {accuracy:.2f}")
    
    # Save test predictions for analysis
    predictions_path = output_path / 'test_predictions.json'
    with open(predictions_path, 'w') as f:
        json.dump(test_predictions, f, indent=2)
    
    # Save model metadata
    metadata = {
        'train_size': len(train_data),
        'test_size': len(test_data),
        'accuracy': accuracy,
        'class_distribution': df['severity'].value_counts().to_dict(),
        'features': ['title', 'description', 'details']
    }
    
    metadata_path = output_path / 'model_metadata.json'
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    return {
        'accuracy': accuracy,
        'train_size': len(train_data),
        'test_size': len(test_data),
        'output_dir': str(output_path)
    }

def main():
    """Main function to train the AI model."""
    parser = argparse.ArgumentParser(description='Train AI model for mobile security analysis')
    parser.add_argument(
        '--data-path',
        type=str,
        help='Path to training data JSON file (if not provided, synthetic data will be used)'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default='models/ai',
        help='Directory to save the trained model (default: models/ai)'
    )
    parser.add_argument(
        '--test-size',
        type=float,
        default=0.2,
        help='Proportion of data to use for testing (default: 0.2)'
    )
    parser.add_argument(
        '--random-state',
        type=int,
        default=42,
        help='Random seed for reproducibility (default: 42)'
    )
    
    args = parser.parse_args()
    
    # Load training data
    if args.data_path:
        logger.info(f"Loading training data from {args.data_path}")
        training_data = load_training_data(args.data_path)
    else:
        logger.warning("No training data provided. Using synthetic data for demonstration.")
        training_data = generate_synthetic_data()
    
    if not training_data:
        logger.error("No training data available. Exiting.")
        return 1
    
    logger.info(f"Loaded {len(training_data)} training examples")
    
    # Train the model
    try:
        results = train_model(
            training_data=training_data,
            output_dir=args.output_dir,
            test_size=args.test_size,
            random_state=args.random_state
        )
        
        logger.info(f"Model training complete. Results: {json.dumps(results, indent=2)}")
        logger.info(f"Model saved to: {results['output_dir']}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during model training: {str(e)}", exc_info=True)
        return 1

if __name__ == '__main__':
    sys.exit(main())
