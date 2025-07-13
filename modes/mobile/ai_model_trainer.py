"""
AI Model Trainer for Mobile Security Analysis.

This module provides functionality to train and evaluate machine learning models
for detecting security issues in mobile applications.
"""
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder
import joblib

from ..models import Finding, Severity

logger = logging.getLogger(__name__)

class AIModelTrainer:
    """Train and evaluate machine learning models for security analysis."""
    
    def __init__(self, model_dir: str = "models"):
        """Initialize the AI model trainer.
        
        Args:
            model_dir: Directory to save/load models
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words='english',
            lowercase=True
        )
        self.label_encoder = LabelEncoder()
        self.models = {
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=100, random_state=42)
        }
        self.best_model = None
        self.best_model_name = None
    
    def extract_features(self, findings: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Extract features from security findings.
        
        Args:
            findings: List of security findings with 'title' and 'description'
            
        Returns:
            Tuple of (features, labels)
        """
        # Prepare text data
        texts = [
            f"{f.get('title', '')} {f.get('description', '')}"
            for f in findings
        ]
        
        # Extract features using TF-IDF
        X = self.vectorizer.fit_transform(texts)
        
        # Encode labels
        labels = [f.get('severity', 'info').lower() for f in findings]
        y = self.label_encoder.fit_transform(labels)
        
        return X, y
    
    def train_models(self, findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
        """Train and evaluate multiple models.
        
        Args:
            findings: List of security findings with 'title', 'description', and 'severity'
            
        Returns:
            Dictionary of model names to their evaluation metrics
        """
        # Extract features and labels
        X, y = self.extract_features(findings)
        
        # Split data into train and test sets
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train and evaluate each model
        results = {}
        best_accuracy = 0
        
        for model_name, model in self.models.items():
            logger.info(f"Training {model_name}...")
            
            # Train the model
            model.fit(X_train, y_train)
            
            # Make predictions
            y_pred = model.predict(X_test)
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_test, y_pred, average='weighted'
            )
            
            # Store results
            results[model_name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1
            }
            
            # Update best model
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                self.best_model = model
                self.best_model_name = model_name
            
            logger.info(f"{model_name} - Accuracy: {accuracy:.4f}, F1: {f1:.4f}")
        
        # Save the best model
        if self.best_model:
            self._save_model(self.best_model, self.best_model_name)
        
        return results
    
    def predict_severity(self, finding: Dict[str, Any]) -> str:
        """Predict the severity of a security finding.
        
        Args:
            finding: Dictionary containing 'title' and 'description'
            
        Returns:
            Predicted severity level (e.g., 'high', 'medium', 'low', 'info')
        """
        if not self.best_model:
            self._load_best_model()
            
        if not self.best_model:
            raise ValueError("No trained model available. Train a model first.")
        
        # Prepare input
        text = f"{finding.get('title', '')} {finding.get('description', '')}"
        X = self.vectorizer.transform([text])
        
        # Make prediction
        y_pred = self.best_model.predict(X)
        severity = self.label_encoder.inverse_transform(y_pred)[0]
        
        return severity
    
    def save(self, output_dir: Optional[str] = None) -> None:
        """Save the model trainer state.
        
        Args:
            output_dir: Directory to save the model and related files
        """
        output_dir = Path(output_dir) if output_dir else self.model_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save the best model
        if self.best_model and self.best_model_name:
            self._save_model(self.best_model, self.best_model_name, output_dir)
        
        # Save the vectorizer
        vectorizer_path = output_dir / 'tfidf_vectorizer.joblib'
        joblib.dump(self.vectorizer, vectorizer_path)
        
        # Save the label encoder
        label_encoder_path = output_dir / 'label_encoder.joblib'
        joblib.dump(self.label_encoder, label_encoder_path)
        
        # Save metadata
        metadata = {
            'best_model': self.best_model_name,
            'models_trained': list(self.models.keys())
        }
        
        metadata_path = output_dir / 'metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    @classmethod
    def load(cls, model_dir: str) -> 'AIModelTrainer':
        """Load a trained model trainer.
        
        Args:
            model_dir: Directory containing the saved model and related files
            
        Returns:
            AIModelTrainer instance with loaded models
        """
        model_dir = Path(model_dir)
        
        # Load metadata
        metadata_path = model_dir / 'metadata.json'
        with open(metadata_path) as f:
            metadata = json.load(f)
        
        # Create instance
        trainer = cls(model_dir=model_dir)
        
        # Load vectorizer
        vectorizer_path = model_dir / 'tfidf_vectorizer.joblib'
        trainer.vectorizer = joblib.load(vectorizer_path)
        
        # Load label encoder
        label_encoder_path = model_dir / 'label_encoder.joblib'
        trainer.label_encoder = joblib.load(label_encoder_path)
        
        # Load best model
        best_model_name = metadata.get('best_model')
        if best_model_name:
            trainer.best_model_name = best_model_name
            trainer.best_model = trainer._load_model(best_model_name, model_dir)
        
        return trainer
    
    def _save_model(self, model: Any, name: str, output_dir: Optional[Path] = None) -> None:
        """Save a trained model.
        
        Args:
            model: Trained model to save
            name: Name of the model
            output_dir: Directory to save the model
        """
        output_dir = output_dir or self.model_dir
        model_path = output_dir / f"{name}_model.joblib"
        joblib.dump(model, model_path)
    
    def _load_model(self, name: str, model_dir: Path) -> Any:
        """Load a trained model.
        
        Args:
            name: Name of the model to load
            model_dir: Directory containing the saved model
            
        Returns:
            Loaded model
        """
        model_path = model_dir / f"{name}_model.joblib"
        return joblib.load(model_path)
    
    def _load_best_model(self) -> None:
        """Load the best performing model."""
        metadata_path = self.model_dir / 'metadata.json'
        
        if not metadata_path.exists():
            raise FileNotFoundError(f"No model metadata found at {metadata_path}")
        
        with open(metadata_path) as f:
            metadata = json.load(f)
        
        best_model_name = metadata.get('best_model')
        if not best_model_name:
            raise ValueError("No best model specified in metadata")
        
        self.best_model = self._load_model(best_model_name, self.model_dir)
        self.best_model_name = best_model_name


def train_severity_classifier(
    training_data: List[Dict[str, Any]],
    output_dir: str = "models/severity_classifier"
) -> AIModelTrainer:
    """Train a severity classifier model.
    
    Args:
        training_data: List of training examples with 'title', 'description', and 'severity'
        output_dir: Directory to save the trained model
        
    Returns:
        Trained AIModelTrainer instance
    """
    # Initialize trainer
    trainer = AIModelTrainer(model_dir=output_dir)
    
    # Train models
    results = trainer.train_models(training_data)
    
    # Save the best model
    trainer.save()
    
    logger.info(f"Training complete. Best model: {trainer.best_model_name}")
    logger.info(f"Results: {json.dumps(results, indent=2)}")
    
    return trainer


def load_severity_classifier(model_dir: str = "models/severity_classifier") -> AIModelTrainer:
    """Load a trained severity classifier.
    
    Args:
        model_dir: Directory containing the saved model
        
    Returns:
        Loaded AIModelTrainer instance
    """
    return AIModelTrainer.load(model_dir)
