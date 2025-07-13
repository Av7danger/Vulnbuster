"""
AI-Powered Security Analyzer for Mobile Applications.

This module provides AI-driven analysis of mobile applications for security vulnerabilities,
combining static and dynamic analysis with machine learning models to identify potential
security issues that traditional scanners might miss.
"""
import asyncio
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set

import numpy as np
from androguard.core.bytecodes.apk import APK
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline

from ..models import Finding, Severity, Platform
from .frida_manager import FridaScriptManager

logger = logging.getLogger(__name__)

class AnalysisType(Enum):
    """Types of analysis that can be performed."""
    STATIC = "static"
    DYNAMIC = "dynamic"
    BEHAVIORAL = "behavioral"
    AI = "ai"

@dataclass
class AITrainingData:
    """Training data for AI models."""
    features: List[Dict[str, Any]]
    labels: List[int]  # 0 for benign, 1 for malicious
    feature_names: List[str]
    model: Optional[Any] = None
    vectorizer: Optional[Any] = None

class AIAnalyzer:
    """AI-powered security analyzer for mobile applications."""
    
    def __init__(self, platform: Platform, package_name: str, frida_manager: FridaScriptManager = None):
        """Initialize the AI analyzer.
        
        Args:
            platform: The target platform (Android/iOS).
            package_name: The package name or bundle ID of the target app.
            frida_manager: Optional FridaScriptManager instance for dynamic analysis.
        """
        self.platform = platform
        self.package_name = package_name
        self.frida_manager = frida_manager or FridaScriptManager()
        self.models: Dict[str, Any] = {}
        self.training_data: Dict[str, AITrainingData] = {}
        self._init_models()
    
    def _init_models(self) -> None:
        """Initialize AI models for different analysis types."""
        # Initialize models for different analysis types
        self.models = {
            "permission_analysis": self._create_permission_model(),
            "api_usage": self._create_api_usage_model(),
            "network_behavior": self._create_network_behavior_model(),
            "code_patterns": self._create_code_pattern_model()
        }
        
        # Initialize training data structures
        self.training_data = {
            "permission_analysis": AITrainingData([], [], []),
            "api_usage": AITrainingData([], [], []),
            "network_behavior": AITrainingData([], [], []),
            "code_patterns": AITrainingData([], [], [])
        }
    
    def _create_permission_model(self) -> Pipeline:
        """Create a model for permission analysis."""
        return Pipeline([
            ('tfidf', TfidfVectorizer()),
            ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
        ])
    
    def _create_api_usage_model(self) -> Pipeline:
        """Create a model for API usage analysis."""
        return Pipeline([
            ('tfidf', TfidfVectorizer()),
            ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
        ])
    
    def _create_network_behavior_model(self) -> Pipeline:
        """Create a model for network behavior analysis."""
        from sklearn.preprocessing import StandardScaler
        from sklearn.svm import SVC
        
        return Pipeline([
            ('scaler', StandardScaler()),
            ('clf', SVC(probability=True, random_state=42))
        ])
    
    def _create_code_pattern_model(self) -> Pipeline:
        """Create a model for code pattern analysis."""
        from sklearn.feature_extraction.text import HashingVectorizer
        
        return Pipeline([
            ('hash', HashingVectorizer(n_features=1000, ngram_range=(1, 3))),
            ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
        ])
    
    async def analyze(self, analysis_type: AnalysisType = AnalysisType.AI) -> List[Finding]:
        """Perform AI-powered security analysis.
        
        Args:
            analysis_type: Type of analysis to perform.
            
        Returns:
            List of security findings.
        """
        findings = []
        
        if analysis_type in [AnalysisType.STATIC, AnalysisType.AI]:
            findings.extend(await self._static_analysis())
        
        if analysis_type in [AnalysisType.DYNAMIC, AnalysisType.AI] and self.frida_manager:
            findings.extend(await self._dynamic_analysis())
        
        if analysis_type in [AnalysisType.BEHAVIORAL, AnalysisType.AI]:
            findings.extend(await self._behavioral_analysis())
        
        if analysis_type == AnalysisType.AI:
            findings.extend(await self._ai_enhanced_analysis(findings))
        
        return findings
    
    async def _static_analysis(self) -> List[Finding]:
        """Perform static analysis of the application."""
        findings = []
        
        try:
            if self.platform == Platform.ANDROID:
                apk_path = await self._get_apk_path()
                if apk_path:
                    apk = APK(apk_path)
                    
                    # Analyze permissions
                    findings.extend(self._analyze_permissions(apk))
                    
                    # Analyze components
                    findings.extend(self._analyze_components(apk))
                    
                    # Analyze manifest
                    findings.extend(self._analyze_manifest(apk))
                    
                    # Analyze native libraries
                    findings.extend(await self._analyze_native_libs(apk))
            
            elif self.platform == Platform.IOS:
                # iOS static analysis would go here
                pass
            
        except Exception as e:
            logger.error(f"Error during static analysis: {str(e)}", exc_info=True)
            findings.append(
                Finding(
                    title="Static Analysis Failed",
                    description=f"An error occurred during static analysis: {str(e)}",
                    severity=Severity.MEDIUM,
                    context={"error": str(e), "analysis_type": "static"}
                )
            )
        
        return findings
    
    async def _dynamic_analysis(self) -> List[Finding]:
        """Perform dynamic analysis of the application."""
        findings = []
        
        try:
            if not self.frida_manager:
                raise ValueError("Frida manager not initialized")
            
            # Start dynamic analysis session
            session_id = await self.frida_manager.attach(self.package_name)
            
            # Load dynamic analysis scripts
            script_id = await self.frida_manager.load_script(
                session_id,
                "dynamic_analysis",
                self._get_dynamic_analysis_script()
            )
            
            # Monitor API calls
            api_findings = await self._monitor_api_calls()
            findings.extend(api_findings)
            
            # Analyze network traffic
            network_findings = await self._analyze_network_traffic()
            findings.extend(network_findings)
            
            # Unload script when done
            await self.frida_manager.unload_script(script_id)
            
        except Exception as e:
            logger.error(f"Error during dynamic analysis: {str(e)}", exc_info=True)
            findings.append(
                Finding(
                    title="Dynamic Analysis Failed",
                    description=f"An error occurred during dynamic analysis: {str(e)}",
                    severity=Severity.MEDIUM,
                    context={"error": str(e), "analysis_type": "dynamic"}
                )
            )
        
        return findings
    
    async def _behavioral_analysis(self) -> List[Finding]:
        """Perform behavioral analysis of the application."""
        findings = []
        
        try:
            # Analyze user interaction patterns
            interaction_findings = await self._analyze_user_interactions()
            findings.extend(interaction_findings)
            
            # Analyze resource usage
            resource_findings = await self._analyze_resource_usage()
            findings.extend(resource_findings)
            
            # Analyze background behavior
            background_findings = await self._analyze_background_behavior()
            findings.extend(background_findings)
            
        except Exception as e:
            logger.error(f"Error during behavioral analysis: {str(e)}", exc_info=True)
            findings.append(
                Finding(
                    title="Behavioral Analysis Failed",
                    description=f"An error occurred during behavioral analysis: {str(e)}",
                    severity=Severity.MEDIUM,
                    context={"error": str(e), "analysis_type": "behavioral"}
                )
            )
        
        return findings
    
    async def _ai_enhanced_analysis(self, existing_findings: List[Finding]) -> List[Finding]:
        """Perform AI-enhanced analysis of the application."""
        findings = []
        
        try:
            # Train models if needed
            await self._train_models()
            
            # Generate features for AI analysis
            features = self._extract_features(existing_findings)
            
            # Make predictions using AI models
            predictions = self._make_predictions(features)
            
            # Generate findings from predictions
            ai_findings = self._generate_findings_from_predictions(predictions)
            findings.extend(ai_findings)
            
            # Correlate findings
            correlated_findings = self._correlate_findings(existing_findings + ai_findings)
            findings.extend(correlated_findings)
            
        except Exception as e:
            logger.error(f"Error during AI-enhanced analysis: {str(e)}", exc_info=True)
            findings.append(
                Finding(
                    title="AI Analysis Failed",
                    description=f"An error occurred during AI-enhanced analysis: {str(e)}",
                    severity=Severity.MEDIUM,
                    context={"error": str(e), "analysis_type": "ai"}
                )
            )
        
        return findings
    
    async def _train_models(self) -> None:
        """Train AI models with available training data."""
        for model_name, model in self.models.items():
            training_data = self.training_data.get(model_name)
            
            if training_data and training_data.features and training_data.labels:
                try:
                    # Convert features to the format expected by the model
                    if isinstance(model.steps[0][1], TfidfVectorizer):
                        # For text features
                        X = [' '.join(str(f) for f in feat.values()) for feat in training_data.features]
                        model.fit(X, training_data.labels)
                    else:
                        # For numerical features
                        X = np.array([[f for f in feat.values()] for feat in training_data.features])
                        model.fit(X, training_data.labels)
                    
                    logger.info(f"Trained {model_name} model with {len(training_data.labels)} samples")
                    
                except Exception as e:
                    logger.error(f"Error training {model_name} model: {str(e)}", exc_info=True)
    
    def _extract_features(self, findings: List[Finding]) -> Dict[str, Any]:
        """Extract features from findings for AI analysis."""
        features = {
            "permissions": set(),
            "apis": set(),
            "network_endpoints": set(),
            "code_patterns": set(),
            "findings_count": len(findings),
            "high_severity_count": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium_severity_count": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low_severity_count": sum(1 for f in findings if f.severity == Severity.LOW),
            "info_severity_count": sum(1 for f in findings if f.severity == Severity.INFO)
        }
        
        for finding in findings:
            # Extract permissions
            if "permissions" in finding.context:
                features["permissions"].update(finding.context["permissions"])
            
            # Extract APIs
            if "apis" in finding.context:
                features["apis"].update(finding.context["apis"])
            
            # Extract network endpoints
            if "endpoints" in finding.context:
                features["network_endpoints"].update(finding.context["endpoints"])
            
            # Extract code patterns
            if "code_patterns" in finding.context:
                features["code_patterns"].update(finding.context["code_patterns"])
        
        # Convert sets to lists for JSON serialization
        features["permissions"] = list(features["permissions"])
        features["apis"] = list(features["apis"])
        features["network_endpoints"] = list(features["network_endpoints"])
        features["code_patterns"] = list(features["code_patterns"])
        
        return features
    
    def _make_predictions(self, features: Dict[str, Any]) -> Dict[str, float]:
        """Make predictions using AI models."""
        predictions = {}
        
        # Make predictions using each model
        for model_name, model in self.models.items():
            try:
                if model_name == "permission_analysis" and features["permissions"]:
                    # Predict based on permissions
                    X = [" ".join(features["permissions"])]
                    proba = model.predict_proba(X)[0][1]  # Probability of being malicious
                    predictions["permission_risk"] = float(proba)
                
                elif model_name == "api_usage" and features["apis"]:
                    # Predict based on API usage
                    X = [" ".join(features["apis"])]
                    proba = model.predict_proba(X)[0][1]
                    predictions["api_risk"] = float(proba)
                
                elif model_name == "network_behavior" and features["network_endpoints"]:
                    # Predict based on network behavior
                    X = [[
                        len(features["network_endpoints"]),
                        features["high_severity_count"],
                        features["medium_severity_count"],
                        features["low_severity_count"]
                    ]]
                    proba = model.predict_proba(X)[0][1]
                    predictions["network_risk"] = float(proba)
                
                elif model_name == "code_patterns" and features["code_patterns"]:
                    # Predict based on code patterns
                    X = [" ".join(features["code_patterns"])]
                    proba = model.predict_proba(X)[0][1]
                    predictions["code_risk"] = float(proba)
                
            except Exception as e:
                logger.error(f"Error making prediction with {model_name}: {str(e)}", exc_info=True)
        
        # Calculate overall risk score (weighted average)
        if predictions:
            weights = {
                "permission_risk": 0.3,
                "api_risk": 0.3,
                "network_risk": 0.2,
                "code_risk": 0.2
            }
            
            total_weight = 0
            weighted_sum = 0
            
            for risk_type, weight in weights.items():
                if risk_type in predictions:
                    weighted_sum += predictions[risk_type] * weight
                    total_weight += weight
            
            if total_weight > 0:
                predictions["overall_risk"] = weighted_sum / total_weight
            else:
                predictions["overall_risk"] = 0.0
        
        return predictions
    
    def _generate_findings_from_predictions(self, predictions: Dict[str, float]) -> List[Finding]:
        """Generate findings from model predictions."""
        findings = []
        
        # Generate findings based on risk scores
        for risk_type, score in predictions.items():
            if risk_type == "overall_risk":
                continue
                
            severity = self._get_severity_from_score(score)
            
            finding = Finding(
                title=f"AI-Detected {risk_type.replace('_', ' ').title()}",
                description=(
                    f"The AI model detected potential security issues based on {risk_type.replace('_', ' ')}. "
                    f"Risk score: {score:.2f}"
                ),
                severity=severity,
                context={
                    "risk_type": risk_type,
                    "risk_score": score,
                    "analysis_type": "ai"
                }
            )
            
            findings.append(finding)
        
        # Add overall risk finding
        if "overall_risk" in predictions:
            overall_risk = predictions["overall_risk"]
            severity = self._get_severity_from_score(overall_risk)
            
            finding = Finding(
                title="AI-Generated Overall Risk Assessment",
                description=(
                    f"The AI model calculated an overall risk score of {overall_risk:.2f} "
                    "based on multiple security factors."
                ),
                severity=severity,
                context={
                    "risk_type": "overall_risk",
                    "risk_score": overall_risk,
                    "analysis_type": "ai",
                    "recommendation": (
                        "Review the detailed AI findings and consider additional manual testing "
                        "for high-risk areas."
                    )
                }
            )
            
            findings.append(finding)
        
        return findings
    
    def _correlate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Correlate related findings to identify complex attack vectors."""
        correlated_findings = []
        
        # Group findings by category
        categories = {}
        for finding in findings:
            category = finding.context.get("category", "other")
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)
        
        # Look for correlations between categories
        if "network" in categories and "data_storage" in categories:
            # Example: Network traffic with sensitive data storage
            network_findings = categories["network"]
            storage_findings = categories["data_storage"]
            
            # Check for unencrypted sensitive data in network traffic
            sensitive_data_findings = [
                f for f in network_findings 
                if f.severity in [Severity.HIGH, Severity.CRITICAL] 
                and "sensitive_data" in f.context
            ]
            
            if sensitive_data_findings and storage_findings:
                finding = Finding(
                    title="Potential Data Exfiltration Risk",
                    description=(
                        "The application stores sensitive data and was observed sending similar data "
                        "over the network. This could indicate potential data exfiltration."
                    ),
                    severity=Severity.HIGH,
                    context={
                        "category": "data_exfiltration",
                        "related_findings": [f.id for f in sensitive_data_findings + storage_findings],
                        "recommendation": (
                            "Review the identified network endpoints and data storage practices. "
                            "Ensure sensitive data is properly encrypted in transit and at rest. "
                            "Implement certificate pinning and use secure communication protocols."
                        )
                    }
                )
                
                correlated_findings.append(finding)
        
        # Add more correlation rules as needed
        
        return correlated_findings
    
    def _get_severity_from_score(self, score: float) -> Severity:
        """Convert a risk score to a severity level."""
        if score >= 0.8:
            return Severity.CRITICAL
        elif score >= 0.6:
            return Severity.HIGH
        elif score >= 0.4:
            return Severity.MEDIUM
        elif score >= 0.2:
            return Severity.LOW
        else:
            return Severity.INFO
    
    # Helper methods for analysis
    
    async def _get_apk_path(self) -> Optional[str]:
        """Get the path to the APK for the target package."""
        if self.platform != Platform.ANDROID:
            return None
        
        try:
            # Try to find the APK on the device
            process = await asyncio.create_subprocess_exec(
                "adb", "shell", "pm", "path
