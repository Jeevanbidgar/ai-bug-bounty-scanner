# Enhanced ML-Powered Security Agent
"""
Machine Learning enhanced security agent using AI for vulnerability prediction and analysis
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import tensorflow as tf
from transformers import pipeline, AutoTokenizer, AutoModel
import requests
import json
import re
from typing import Dict, List, Any, Tuple
import logging

class MLSecurityAgent:
    """ML-powered security agent for intelligent vulnerability detection"""
    
    def __init__(self):
        self.vulnerability_classifier = None
        self.anomaly_detector = None
        self.text_vectorizer = TfidfVectorizer(max_features=1000)
        self.sentiment_analyzer = pipeline("sentiment-analysis")
        
        # Initialize pre-trained models
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize machine learning models"""
        # Vulnerability classification model
        self.vulnerability_classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42
        )
        
        # Anomaly detection for unusual patterns
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
        logging.info("ML models initialized successfully")
    
    async def intelligent_vulnerability_analysis(self, response_data: Dict) -> Dict:
        """Analyze responses using ML to detect potential vulnerabilities"""
        
        # Extract features from response
        features = self._extract_response_features(response_data)
        
        # Predict vulnerability likelihood
        vuln_probability = self._predict_vulnerability(features)
        
        # Detect anomalies
        is_anomaly = self._detect_anomaly(features)
        
        # Analyze response content with NLP
        content_analysis = self._analyze_content_with_nlp(response_data.get('content', ''))
        
        return {
            'vulnerability_probability': vuln_probability,
            'is_anomalous': is_anomaly,
            'content_analysis': content_analysis,
            'ml_confidence': self._calculate_confidence(features),
            'recommended_tests': self._recommend_tests(features)
        }
    
    def _extract_response_features(self, response_data: Dict) -> np.ndarray:
        """Extract numerical features from HTTP response"""
        features = []
        
        # Response code features
        status_code = response_data.get('status_code', 200)
        features.append(status_code)
        features.append(1 if status_code >= 400 else 0)  # Error status
        
        # Response size features
        content_length = len(response_data.get('content', ''))
        features.append(content_length)
        features.append(np.log(content_length + 1))  # Log transform
        
        # Response time features
        response_time = response_data.get('response_time', 0)
        features.append(response_time)
        
        # Header analysis
        headers = response_data.get('headers', {})
        features.append(len(headers))
        features.append(1 if 'X-Frame-Options' not in headers else 0)
        features.append(1 if 'Content-Security-Policy' not in headers else 0)
        
        # Content analysis
        content = response_data.get('content', '').lower()
        features.append(content.count('error'))
        features.append(content.count('exception'))
        features.append(content.count('sql'))
        features.append(content.count('mysql'))
        features.append(content.count('warning'))
        
        return np.array(features).reshape(1, -1)
    
    def _predict_vulnerability(self, features: np.ndarray) -> float:
        """Predict vulnerability likelihood using trained model"""
        # In a real implementation, this would use a pre-trained model
        # For demo, using a simple heuristic
        feature_sum = np.sum(features)
        return min(1.0, feature_sum / 1000.0)
    
    def _detect_anomaly(self, features: np.ndarray) -> bool:
        """Detect if response pattern is anomalous"""
        # Train on normal patterns and detect outliers
        try:
            prediction = self.anomaly_detector.predict(features)
            return prediction[0] == -1  # -1 indicates anomaly
        except:
            return False
    
    def _analyze_content_with_nlp(self, content: str) -> Dict:
        """Analyze response content using NLP techniques"""
        if not content:
            return {'sentiment': 'neutral', 'security_keywords': []}
        
        # Sentiment analysis
        try:
            sentiment = self.sentiment_analyzer(content[:512])  # Limit to 512 chars
            sentiment_score = sentiment[0]['score']
            sentiment_label = sentiment[0]['label']
        except:
            sentiment_score = 0.5
            sentiment_label = 'neutral'
        
        # Security keyword detection
        security_keywords = self._find_security_keywords(content)
        
        return {
            'sentiment': sentiment_label,
            'sentiment_score': sentiment_score,
            'security_keywords': security_keywords,
            'suspicious_patterns': self._find_suspicious_patterns(content)
        }
    
    def _find_security_keywords(self, content: str) -> List[str]:
        """Find security-related keywords in content"""
        keywords = [
            'error', 'exception', 'stack trace', 'debug', 'warning',
            'sql', 'mysql', 'postgres', 'oracle', 'database',
            'admin', 'password', 'token', 'key', 'secret',
            'injection', 'xss', 'csrf', 'directory traversal'
        ]
        
        found_keywords = []
        content_lower = content.lower()
        
        for keyword in keywords:
            if keyword in content_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def _find_suspicious_patterns(self, content: str) -> List[str]:
        """Find suspicious patterns that might indicate vulnerabilities"""
        patterns = [
            r'error:\s+.*sql.*syntax',
            r'mysql.*error.*1064',
            r'ora-\d+.*error',
            r'exception.*stack.*trace',
            r'warning.*mysql_.*',
            r'notice.*undefined.*index',
            r'<script.*>.*</script>',
            r'on[a-z]+\s*=\s*["\'].*["\']'
        ]
        
        found_patterns = []
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(pattern)
        
        return found_patterns
    
    def _calculate_confidence(self, features: np.ndarray) -> float:
        """Calculate confidence score for ML predictions"""
        # Simple confidence calculation based on feature variance
        feature_variance = np.var(features)
        return min(1.0, max(0.1, 1.0 - feature_variance / 100.0))
    
    def _recommend_tests(self, features: np.ndarray) -> List[str]:
        """Recommend specific tests based on ML analysis"""
        recommendations = []
        
        # Extract individual features
        status_code = features[0][0]
        content_length = features[0][2]
        error_count = features[0][7]
        sql_count = features[0][9]
        
        if status_code >= 500:
            recommendations.append("Server Error Analysis")
        
        if error_count > 0:
            recommendations.append("Error Message Analysis")
        
        if sql_count > 0:
            recommendations.append("SQL Injection Testing")
        
        if content_length > 10000:
            recommendations.append("Information Disclosure Check")
        
        return recommendations

    async def train_on_scan_results(self, scan_results: List[Dict]):
        """Train ML models on previous scan results"""
        if not scan_results:
            return
        
        # Extract features and labels from historical data
        features_list = []
        labels = []
        
        for result in scan_results:
            features = self._extract_response_features(result)
            features_list.append(features.flatten())
            
            # Label: 1 if vulnerability found, 0 otherwise
            label = 1 if result.get('vulnerabilities_found', 0) > 0 else 0
            labels.append(label)
        
        if len(features_list) > 10:  # Need minimum samples for training
            X = np.array(features_list)
            y = np.array(labels)
            
            # Train vulnerability classifier
            self.vulnerability_classifier.fit(X, y)
            
            # Train anomaly detector on normal patterns only
            normal_features = X[y == 0]
            if len(normal_features) > 5:
                self.anomaly_detector.fit(normal_features)
            
            logging.info(f"ML models trained on {len(features_list)} samples")

    def get_agent_status(self) -> Dict:
        """Get current ML agent status"""
        return {
            'name': 'ML Security Agent',
            'status': 'active',
            'capabilities': [
                'Vulnerability Prediction',
                'Anomaly Detection', 
                'Content Analysis',
                'Pattern Recognition',
                'Smart Test Recommendation'
            ],
            'models_loaded': True,
            'version': '1.0.0'
        }
