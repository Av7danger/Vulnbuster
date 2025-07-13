"""
AI Model Training and Management for Mobile Security Analysis.

This module provides functionality for training, evaluating, and managing
machine learning models used in the mobile security scanner.
"""
import json
import logging
import os
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer, HashingVectorizer
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import (
    classification_report, accuracy_score, precision_recall_fscore_support,
    roc_auc_score, confusion_matrix
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.svm import SVC
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
import joblib

from ..models import Finding, Severity

logger = logging.getLogger(__name__)

class AIModelType(Enum):
    """Types of AI models supported."""
    RANDOM_FOREST = "random_forest"
    XGBOOST = "xgboost"
    SVM = "svm"
    ISOLATION_FOREST = "isolation_forest"
    GRADIENT_BOOSTING = "gradient_boosting"

class FeatureType(Enum):
    """Types of features for model training."""
    TEXT = "text"
    NUMERICAL = "numerical"
    CATEGORICAL = "categorical"
    SEQUENCE = "sequence"

@dataclass
class TrainingConfig:
    """Configuration for model training."""
    model_type: AIModelType
    feature_type: FeatureType
    test_size: float = 0.2
    random_state: int = 42
    use_smote: bool = True
    cv_folds: int = 5
    scoring: str = 'f1_weighted'
    n_jobs: int = -1
    param_grid: Optional[Dict] = None
    
    def __post_init__(self):
        """Set default parameter grids if not provided."""
        if self.param_grid is None:
            if self.model_type == AIModelType.RANDOM_FOREST:
                self.param_grid = {
                    'classifier__n_estimators': [50, 100, 200],
                    'classifier__max_depth': [None, 10, 20, 30],
                    'classifier__min_samples_split': [2, 5, 10],
                    'classifier__min_samples_leaf': [1, 2, 4]
                }
            elif self.model_type == AIModelType.XGBOOST:
                self.param_grid = {
                    'classifier__n_estimators': [50, 100, 200],
                    'classifier__max_depth': [3, 6, 10],
                    'classifier__learning_rate': [0.01, 0.1, 0.3],
                    'classifier__subsample': [0.8, 1.0],
                    'classifier__colsample_bytree': [0.8, 1.0]
                }
            elif self.model_type == AIModelType.SVM:
                self.param_grid = {
                    'classifier__C': [0.1, 1, 10],
                    'classifier__kernel': ['linear', 'rbf'],
                    'classifier__gamma': ['scale', 'auto']
                }
            elif self.model_type == AIModelType.ISOLATION_FOREST:
                self.param_grid = {
                    'classifier__n_estimators': [50, 100, 200],
                    'classifier__max_samples': ['auto', 0.5, 0.8],
                    'classifier__contamination': ['auto', 0.05, 0.1, 0.2]
                }
            elif self.model_type == AIModelType.GRADIENT_BOOSTING:
                self.param_grid = {
                    'classifier__n_estimators': [50, 100, 200],
                    'classifier__learning_rate': [0.01, 0.1, 0.3],
                    'classifier__max_depth': [3, 6, 10],
                    'classifier__min_samples_split': [2, 5, 10],
                    'classifier__min_samples_leaf': [1, 2, 4]
                }

@dataclass
class ModelEvaluation:
    """Evaluation results for a trained model."""
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: Optional[float] = None
    confusion_matrix: Optional[np.ndarray] = None
    classification_report: Optional[Dict] = None
    cross_val_scores: Optional[List[float]] = None
    feature_importances: Optional[Dict[str, float]] = None

class AIModelTrainer:
    """Class for training and managing AI models for mobile security analysis."""
    
    def __init__(self, model_dir: Union[str, Path] = "models"):
        """Initialize the AI model trainer.
        
        Args:
            model_dir: Directory to save/load models.
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.models: Dict[str, Any] = {}
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.feature_processors: Dict[str, Any] = {}
        self.evaluations: Dict[str, ModelEvaluation] = {}
    
    def create_model(self, config: TrainingConfig) -> Any:
        """Create a model pipeline based on the configuration.
        
        Args:
            config: Training configuration.
            
        Returns:
            A scikit-learn compatible model pipeline.
        """
        # Create feature processing steps
        steps = []
        
        # Add feature extraction based on feature type
        if config.feature_type == FeatureType.TEXT:
            steps.append(('vectorizer', TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 2),
                stop_words='english'
            )))
        elif config.feature_type == FeatureType.NUMERICAL:
            steps.append(('scaler', StandardScaler()))
        elif config.feature_type == FeatureType.SEQUENCE:
            steps.append(('vectorizer', HashingVectorizer(
                n_features=1000,
                ngram_range=(1, 3),
                alternate_sign=False
            )))
        
        # Add SMOTE for imbalanced data if enabled
        if config.use_smote:
            steps.append(('smote', SMOTE(random_state=config.random_state)))
        
        # Add classifier based on model type
        if config.model_type == AIModelType.RANDOM_FOREST:
            classifier = RandomForestClassifier(random_state=config.random_state)
        elif config.model_type == AIModelType.XGBOOST:
            classifier = XGBClassifier(
                random_state=config.random_state,
                use_label_encoder=False,
                eval_metric='logloss',
                n_jobs=config.n_jobs
            )
        elif config.model_type == AIModelType.SVM:
            classifier = SVC(
                probability=True,
                random_state=config.random_state,
                class_weight='balanced'
            )
        elif config.model_type == AIModelType.ISOLATION_FOREST:
            classifier = IsolationForest(
                random_state=config.random_state,
                n_jobs=config.n_jobs,
                contamination='auto'
            )
        elif config.model_type == AIModelType.GRADIENT_BOOSTING:
            classifier = GradientBoostingClassifier(random_state=config.random_state)
        else:
            raise ValueError(f"Unsupported model type: {config.model_type}")
        
        steps.append(('classifier', classifier))
        
        # Create pipeline
        if config.use_smote:
            pipeline = ImbPipeline(steps)
        else:
            pipeline = Pipeline(steps)
        
        return pipeline
    
    def train_model(
        self,
        X_train: Union[np.ndarray, pd.DataFrame, List[str]],
        y_train: Union[np.ndarray, List],
        config: TrainingConfig,
        model_name: str,
        feature_names: Optional[List[str]] = None,
        save_model: bool = True
    ) -> Tuple[Any, ModelEvaluation]:
        """Train a model with the given data and configuration.
        
        Args:
            X_train: Training features.
            y_train: Training labels.
            config: Training configuration.
            model_name: Name to identify the trained model.
            feature_names: Names of the features (for interpretability).
            save_model: Whether to save the trained model.
            
        Returns:
            A tuple of (trained_model, evaluation_metrics)
        """
        logger.info(f"Training {model_name} model with {len(X_train)} samples...")
        
        # Convert to numpy arrays if needed
        if not isinstance(X_train, (np.ndarray, pd.DataFrame)):
            X_train = np.array(X_train)
        
        if not isinstance(y_train, np.ndarray):
            y_train = np.array(y_train)
        
        # Encode labels if needed
        if y_train.dtype == object or y_train.dtype.type == np.str_:
            label_encoder = LabelEncoder()
            y_train_encoded = label_encoder.fit_transform(y_train)
            self.label_encoders[model_name] = label_encoder
        else:
            y_train_encoded = y_train
        
        # Create and train model
        model = self.create_model(config)
        
        # Hyperparameter tuning with GridSearchCV
        grid_search = GridSearchCV(
            estimator=model,
            param_grid=config.param_grid,
            cv=config.cv_folds,
            scoring=config.scoring,
            n_jobs=config.n_jobs,
            verbose=1
        )
        
        # Fit the model
        grid_search.fit(X_train, y_train_encoded)
        
        # Get the best model
        best_model = grid_search.best_estimator_
        
        # Cross-validation scores
        cv_scores = cross_val_score(
            best_model, X_train, y_train_encoded,
            cv=config.cv_folds, scoring=config.scoring, n_jobs=config.n_jobs
        )
        
        # Make predictions on training data
        y_pred = best_model.predict(X_train)
        y_pred_proba = best_model.predict_proba(X_train) if hasattr(best_model, 'predict_proba') else None
        
        # Calculate metrics
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_train_encoded, y_pred, average='weighted', zero_division=0
        )
        
        accuracy = accuracy_score(y_train_encoded, y_pred)
        
        # Calculate ROC AUC if possible
        roc_auc = None
        if y_pred_proba is not None and len(np.unique(y_train_encoded)) > 1:
            try:
                roc_auc = roc_auc_score(
                    y_train_encoded, y_pred_proba, multi_class='ovr', average='weighted'
                )
            except Exception as e:
                logger.warning(f"Could not calculate ROC AUC: {str(e)}")
        
        # Get feature importances if available
        feature_importances = None
        try:
            if hasattr(best_model.named_steps['classifier'], 'feature_importances_'):
                importances = best_model.named_steps['classifier'].feature_importances_
                
                # Get feature names
                if feature_names is not None and len(feature_names) == len(importances):
                    feature_importances = dict(zip(feature_names, importances))
                else:
                    # Try to get feature names from the vectorizer if it exists
                    if 'vectorizer' in best_model.named_steps:
                        try:
                            feature_names = best_model.named_steps['vectorizer'].get_feature_names_out()
                            if len(feature_names) == len(importances):
                                feature_importances = dict(zip(feature_names, importances))
                        except Exception as e:
                            logger.warning(f"Could not get feature names: {str(e)}")
        except Exception as e:
            logger.warning(f"Could not extract feature importances: {str(e)}")
        
        # Create evaluation results
        evaluation = ModelEvaluation(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            roc_auc=roc_auc,
            confusion_matrix=confusion_matrix(y_train_encoded, y_pred),
            classification_report=classification_report(
                y_train_encoded, y_pred, output_dict=True, zero_division=0
            ),
            cross_val_scores=cv_scores.tolist(),
            feature_importances=feature_importances
        )
        
        # Save the model and evaluation results
        if save_model:
            self.save_model(best_model, model_name, evaluation)
        
        # Store in memory
        self.models[model_name] = best_model
        self.evaluations[model_name] = evaluation
        
        logger.info(f"Training completed for {model_name}")
        logger.info(f"Best parameters: {grid_search.best_params_}")
        logger.info(f"Cross-validation {config.scoring}: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        logger.info(f"Training accuracy: {accuracy:.4f}")
        logger.info(f"Training F1-score: {f1:.4f}")
        
        return best_model, evaluation
    
    def evaluate_model(
        self,
        model: Any,
        X_test: Union[np.ndarray, pd.DataFrame, List[str]],
        y_test: Union[np.ndarray, List],
        model_name: str = "test_model"
    ) -> ModelEvaluation:
        """Evaluate a trained model on test data.
        
        Args:
            model: Trained model to evaluate.
            X_test: Test features.
            y_test: True labels for test data.
            model_name: Name of the model for reference.
            
        Returns:
            ModelEvaluation object with evaluation metrics.
        """
        logger.info(f"Evaluating {model_name} on test data...")
        
        # Convert to numpy arrays if needed
        if not isinstance(X_test, (np.ndarray, pd.DataFrame)):
            X_test = np.array(X_test)
        
        if not isinstance(y_test, np.ndarray):
            y_test = np.array(y_test)
        
        # Encode labels if needed
        if model_name in self.label_encoders:
            y_test_encoded = self.label_encoders[model_name].transform(y_test)
        else:
            y_test_encoded = y_test
        
        # Make predictions
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test) if hasattr(model, 'predict_proba') else None
        
        # Calculate metrics
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test_encoded, y_pred, average='weighted', zero_division=0
        )
        
        accuracy = accuracy_score(y_test_encoded, y_pred)
        
        # Calculate ROC AUC if possible
        roc_auc = None
        if y_pred_proba is not None and len(np.unique(y_test_encoded)) > 1:
            try:
                roc_auc = roc_auc_score(
                    y_test_encoded, y_pred_proba, multi_class='ovr', average='weighted'
                )
            except Exception as e:
                logger.warning(f"Could not calculate ROC AUC: {str(e)}")
        
        # Create evaluation results
        evaluation = ModelEvaluation(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            roc_auc=roc_auc,
            confusion_matrix=confusion_matrix(y_test_encoded, y_pred),
            classification_report=classification_report(
                y_test_encoded, y_pred, output_dict=True, zero_division=0
            )
        )
        
        # Store evaluation
        self.evaluations[f"{model_name}_test"] = evaluation
        
        logger.info(f"Test evaluation for {model_name}:")
        logger.info(f"  Accuracy: {accuracy:.4f}")
        logger.info(f"  Precision: {precision:.4f}")
        logger.info(f"  Recall: {recall:.4f}")
        logger.info(f"  F1-score: {f1:.4f}")
        if roc_auc is not None:
            logger.info(f"  ROC AUC: {roc_auc:.4f}")
        
        return evaluation
    
    def save_model(self, model: Any, model_name: str, evaluation: Optional[ModelEvaluation] = None) -> None:
        """Save a trained model to disk.
        
        Args:
            model: Trained model to save.
            model_name: Name to save the model as.
            evaluation: Optional evaluation results to save with the model.
        """
        # Create model directory
        model_dir = self.model_dir / model_name
        model_dir.mkdir(parents=True, exist_ok=True)
        
        # Save the model
        model_path = model_dir / 'model.joblib'
        joblib.dump(model, model_path)
        
        # Save evaluation results if provided
        if evaluation is not None:
            eval_path = model_dir / 'evaluation.json'
            eval_data = {
                'accuracy': evaluation.accuracy,
                'precision': evaluation.precision,
                'recall': evaluation.recall,
                'f1': evaluation.f1,
                'roc_auc': evaluation.roc_auc,
                'confusion_matrix': evaluation.confusion_matrix.tolist() if evaluation.confusion_matrix is not None else None,
                'classification_report': evaluation.classification_report,
                'cross_val_scores': evaluation.cross_val_scores,
                'feature_importances': evaluation.feature_importances,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(eval_path, 'w') as f:
                json.dump(eval_data, f, indent=2)
        
        logger.info(f"Model saved to {model_path}")
    
    def load_model(self, model_name: str) -> Tuple[Any, Optional[ModelEvaluation]]:
        """Load a trained model from disk.
        
        Args:
            model_name: Name of the model to load.
            
        Returns:
            A tuple of (model, evaluation)
        """
        model_dir = self.model_dir / model_name
        model_path = model_dir / 'model.joblib'
        eval_path = model_dir / 'evaluation.json'
        
        # Load the model
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        model = joblib.load(model_path)
        
        # Load evaluation results if available
        evaluation = None
        if eval_path.exists():
            with open(eval_path, 'r') as f:
                eval_data = json.load(f)
                
                evaluation = ModelEvaluation(
                    accuracy=eval_data['accuracy'],
                    precision=eval_data['precision'],
                    recall=eval_data['recall'],
                    f1=eval_data['f1'],
                    roc_auc=eval_data.get('roc_auc'),
                    confusion_matrix=np.array(eval_data['confusion_matrix']) if eval_data.get('confusion_matrix') else None,
                    classification_report=eval_data.get('classification_report'),
                    cross_val_scores=eval_data.get('cross_val_scores'),
                    feature_importances=eval_data.get('feature_importances')
                )
        
        # Store in memory
        self.models[model_name] = model
        if evaluation is not None:
            self.evaluations[model_name] = evaluation
        
        logger.info(f"Loaded model: {model_name}")
        return model, evaluation
    
    def get_feature_importance(self, model_name: str, top_n: int = 20) -> Dict[str, float]:
        """Get the top N most important features for a trained model.
        
        Args:
            model_name: Name of the trained model.
            top_n: Number of top features to return.
            
        Returns:
            Dictionary of feature names and their importance scores.
        """
        if model_name not in self.evaluations or not self.evaluations[model_name].feature_importances:
            logger.warning(f"No feature importances available for model: {model_name}")
            return {}
        
        importances = self.evaluations[model_name].feature_importances
        
        # Sort features by importance
        sorted_importances = dict(
            sorted(importances.items(), key=lambda x: x[1], reverse=True)[:top_n]
        )
        
        return sorted_importances
    
    def train_test_split(
        self,
        X: Union[np.ndarray, pd.DataFrame, List],
        y: Union[np.ndarray, List],
        test_size: float = 0.2,
        random_state: int = 42,
        stratify: bool = True
    ) -> Tuple:
        """Split data into training and test sets.
        
        Args:
            X: Feature matrix.
            y: Target labels.
            test_size: Proportion of the dataset to include in the test split.
            random_state: Random seed for reproducibility.
            stratify: Whether to perform stratified splitting.
            
        Returns:
            X_train, X_test, y_train, y_test
        """
        stratify_param = y if stratify else None
        
        return train_test_split(
            X, y,
            test_size=test_size,
            random_state=random_state,
            stratify=stratify_param
        )

# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Example dataset (replace with actual security data)
    from sklearn.datasets import make_classification
    
    # Generate synthetic data
    X, y = make_classification(
        n_samples=1000,
        n_features=20,
        n_informative=10,
        n_redundant=5,
        n_classes=3,
        random_state=42
    )
    
    # Initialize trainer
    trainer = AIModelTrainer(model_dir="security_models")
    
    # Split data
    X_train, X_test, y_train, y_test = trainer.train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Define training configuration
    config = TrainingConfig(
        model_type=AIModelType.RANDOM_FOREST,
        feature_type=FeatureType.NUMERICAL,
        test_size=0.2,
        random_state=42,
        use_smote=True,
        cv_folds=5,
        scoring='f1_weighted',
        n_jobs=-1
    )
    
    # Train model
    model, evaluation = trainer.train_model(
        X_train, y_train,
        config=config,
        model_name="malware_detection",
        feature_names=[f"feature_{i}" for i in range(X_train.shape[1])]
    )
    
    # Evaluate on test set
    test_evaluation = trainer.evaluate_model(
        model, X_test, y_test, "malware_detection"
    )
    
    # Get feature importances
    importances = trainer.get_feature_importance("malware_detection", top_n=10)
    print("\nTop 10 important features:")
    for feature, importance in importances.items():
        print(f"{feature}: {importance:.4f}")
