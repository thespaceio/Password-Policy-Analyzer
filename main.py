# main.py
import os
import re
import json
import hashlib
import requests
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import zxcvbn


class PasswordAnalyzer:
    def __init__(self, config_path='config/policy_config.json'):
        with open(config_path, 'r') as f:
            self.config = json.load(f)

        # Load common passwords
        self.common_passwords = set()
        self.load_common_passwords()

    def load_common_passwords(self):
        """Load common passwords from file"""
        try:
            with open('data/common_passwords.txt', 'r') as f:
                for line in f:
                    self.common_passwords.add(line.strip().lower())
        except FileNotFoundError:
            # Create a basic file if it doesn't exist
            with open('data/common_passwords.txt', 'w') as f:
                f.write('password\n123456\npassword123\n')
            self.load_common_passwords()

    def check_length(self, password):
        """Check password length against policy"""
        min_len = self.config['policy_requirements']['min_length']
        max_len = self.config['policy_requirements']['max_length']

        issues = []
        if len(password) < min_len:
            issues.append(f"Password too short (minimum {min_len} characters)")
        if len(password) > max_len:
            issues.append(f"Password too long (maximum {max_len} characters)")

        return len(password) >= min_len and len(password) <= max_len, issues

    def check_character_requirements(self, password):
        """Check for required character types"""
        reqs = self.config['policy_requirements']
        issues = []

        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

        if reqs['require_uppercase'] and not has_upper:
            issues.append("Missing uppercase letter")
        if reqs['require_lowercase'] and not has_lower:
            issues.append("Missing lowercase letter")
        if reqs['require_numbers'] and not has_digit:
            issues.append("Missing number")
        if reqs['require_special_chars'] and not has_special:
            issues.append("Missing special character")

        return all([
            not reqs['require_uppercase'] or has_upper,
            not reqs['require_lowercase'] or has_lower,
            not reqs['require_numbers'] or has_digit,
            not reqs['require_special_chars'] or has_special
        ]), issues

    def check_repeated_characters(self, password):
        """Check for excessive repeated characters"""
        max_repeats = self.config['policy_requirements']['max_repeated_chars']
        issues = []

        for i in range(len(password) - max_repeats):
            if len(set(password[i:i + max_repeats + 1])) == 1:  # All same character
                issues.append(f"Too many repeated characters (max {max_repeats})")
                break

        return len(password) < 2 or not any(
            len(set(password[i:i + max_repeats + 1])) == 1
            for i in range(len(password) - max_repeats)
        ), issues

    def check_unique_characters(self, password):
        """Check minimum unique characters"""
        min_unique = self.config['policy_requirements']['min_unique_chars']
        unique_chars = len(set(password))
        issues = []

        if unique_chars < min_unique:
            issues.append(f"Too few unique characters (minimum {min_unique}, found {unique_chars})")

        return unique_chars >= min_unique, issues

    def check_common_patterns(self, password):
        """Check for common patterns"""
        issues = []

        patterns = [
            (r'(.)\1{2,}', "Repetitive character pattern detected"),
            (r'(012|123|234|345|456|567|678|789|890)', "Sequential number pattern detected"),
            (r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
             "Sequential letter pattern detected"),
            (r'(qwer|asdf|zxcv|qwer|asdf|zxcv)', "Keyboard pattern detected"),
        ]

        for pattern, message in patterns:
            if re.search(pattern, password.lower()):
                issues.append(message)

        return not any(re.search(pattern, password.lower()) for pattern, _ in patterns), issues

    def check_dictionary_words(self, password):
        """Check against common passwords"""
        issues = []

        if password.lower() in self.common_passwords:
            issues.append("Password is too common")

        return password.lower() not in self.common_passwords, issues

    def check_pwned_password(self, password):
        """Check if password has been compromised using Have I Been Pwned API"""
        try:
            # Use k-anonymity approach
            password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = password_hash[:5], password_hash[5:]

            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")

            if response.status_code == 200:
                hashes = response.text.split('\n')
                for hash_line in hashes:
                    if hash_line.startswith(suffix):
                        count = hash_line.split(':')[1].strip()
                        return False, [f"Password has been compromised {count} times"]

            return True, []
        except Exception as e:
            return True, [f"Could not check against pwned database: {str(e)}"]

    def calculate_zxcvbn_score(self, password):
        """Calculate password strength using zxcvbn library"""
        result = zxcvbn.zxcvbn(password)
        score = result['score']  # 0-4 scale
        feedback = result['feedback']['warning'] if result['feedback']['warning'] else "Strong password"

        # Convert 0-4 scale to 0-100 scale
        strength_percentage = (score / 4) * 100

        return strength_percentage, feedback, result['crack_times_display']['offline_fast_hashing_1e10_per_second']

    def analyze_password(self, password):
        """Analyze password against all policies"""
        results = {
            'password': '*' * len(password),  # Don't expose password in results
            'analysis_timestamp': datetime.now().isoformat(),
            'overall_strength': 0,
            'is_compliant': True,
            'issues': [],
            'strength_details': {},
            'recommendations': []
        }

        # Run all checks
        checks = [
            ('length', self.check_length),
            ('character_requirements', self.check_character_requirements),
            ('repeated_chars', self.check_repeated_characters),
            ('unique_chars', self.check_unique_characters),
            ('patterns', self.check_common_patterns),
            ('dictionary', self.check_dictionary_words),
            ('compromised', self.check_pwned_password)
        ]

        all_passed = True
        all_issues = []

        for check_name, check_func in checks:
            passed, issues = check_func(password)
            if not passed:
                all_passed = False
                all_issues.extend(issues)

        results['is_compliant'] = all_passed
        results['issues'] = all_issues

        # Calculate overall strength
        zxcvbn_score, feedback, crack_time = self.calculate_zxcvbn_score(password)
        results['strength_details']['zxcvbn_score'] = zxcvbn_score
        results['strength_details']['feedback'] = feedback
        results['strength_details']['estimated_crack_time'] = crack_time

        # Determine overall strength level
        thresholds = self.config['strength_thresholds']
        if zxcvbn_score >= thresholds['very_strong']:
            results['overall_strength'] = 'Very Strong'
        elif zxcvbn_score >= thresholds['strong']:
            results['overall_strength'] = 'Strong'
        elif zxcvbn_score >= thresholds['good']:
            results['overall_strength'] = 'Good'
        elif zxcvbn_score >= thresholds['fair']:
            results['overall_strength'] = 'Fair'
        elif zxcvbn_score >= thresholds['weak']:
            results['overall_strength'] = 'Weak'
        else:
            results['overall_strength'] = 'Very Weak'

        # Generate recommendations
        recommendations = []
        if not all_passed:
            recommendations.extend(all_issues)

        if zxcvbn_score < 60:
            recommendations.append("Consider using a longer, more complex password")

        if not any(char.isupper() for char in password):
            recommendations.append("Add uppercase letters")

        if not any(char.isdigit() for char in password):
            recommendations.append("Add numbers")

        if not any(char in "!@#$%^&*(),.?\":{}|<>" for char in password):
            recommendations.append("Add special characters")

        results['recommendations'] = recommendations

        return results

    def generate_policy_compliance_report(self, passwords):
        """Generate a report for multiple passwords"""
        report = {
            'report_timestamp': datetime.now().isoformat(),
            'total_passwords': len(passwords),
            'compliant_passwords': 0,
            'non_compliant_passwords': 0,
            'average_strength': 0,
            'details': []
        }

        total_strength = 0

        for password in passwords:
            analysis = self.analyze_password(password)
            report['details'].append(analysis)

            if analysis['is_compliant']:
                report['compliant_passwords'] += 1
            else:
                report['non_compliant_passwords'] += 1

            # Convert strength to numeric for averaging
            strength_map = {
                'Very Weak': 10, 'Weak': 25, 'Fair': 50,
                'Good': 65, 'Strong': 85, 'Very Strong': 95
            }
            total_strength += strength_map.get(analysis['overall_strength'], 0)

        if passwords:
            report['average_strength'] = total_strength / len(passwords)

        return report


class PasswordPolicyAnalyzer:
    def __init__(self):
        self.analyzer = PasswordAnalyzer()
        self.app = Flask(__name__)
        CORS(self.app)
        self.setup_routes()

    def setup_routes(self):
        @self.app.route('/analyze', methods=['POST'])
        def analyze_password():
            try:
                data = request.json
                password = data.get('password')

                if not password:
                    return jsonify({'error': 'Password is required'}), 400

                result = self.analyzer.analyze_password(password)
                return jsonify(result)

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/batch-analyze', methods=['POST'])
        def batch_analyze():
            try:
                data = request.json
                passwords = data.get('passwords', [])

                if not passwords:
                    return jsonify({'error': 'Password list is required'}), 400

                report = self.analyzer.generate_policy_compliance_report(passwords)
                return jsonify(report)

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/policy-check', methods=['GET'])
        def get_policy():
            try:
                with open('config/policy_config.json', 'r') as f:
                    policy = json.load(f)
                return jsonify(policy['policy_requirements'])
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/health', methods=['GET'])
        def health_check():
            return jsonify({'status': 'healthy', 'service': 'Password Policy Analyzer'})

    def run(self, host='0.0.0.0', port=5001):
        self.app.run(host=host, port=port, debug=False)


def create_directories():
    """Create required directories"""
    os.makedirs('config', exist_ok=True)
    os.makedirs('data', exist_ok=True)
    os.makedirs('reports', exist_ok=True)


if __name__ == "__main__":
    create_directories()

    # Create default config if it doesn't exist
    config_path = 'config/policy_config.json'
    if not os.path.exists(config_path):
        with open(config_path, 'w') as f:
            json.dump({
                "policy_requirements": {
                    "min_length": 8,
                    "max_length": 128,
                    "require_uppercase": True,
                    "require_lowercase": True,
                    "require_numbers": True,
                    "require_special_chars": True,
                    "max_repeated_chars": 2,
                    "min_unique_chars": 6,
                    "avoid_common_patterns": True,
                    "avoid_dictionary_words": True
                },
                "strength_thresholds": {
                    "very_weak": 0,
                    "weak": 20,
                    "fair": 40,
                    "good": 60,
                    "strong": 80,
                    "very_strong": 100
                },
                "external_apis": {
                    "haveibeenpwned": "https://api.pwnedpasswords.com/range/",
                    "common_passwords_url": "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt"
                }
            }, f, indent=2)

    # Create default common passwords file if it doesn't exist
    passwords_path = 'data/common_passwords.txt'
    if not os.path.exists(passwords_path):
        with open(passwords_path, 'w') as f:
            f.write('password\n123456\npassword123\nadmin\nletmein\nwelcome\nmonkey\n1234567890\n')

    # Initialize and run the analyzer
    analyzer = PasswordPolicyAnalyzer()
    print("Starting Password Policy Analyzer...")
    print("API endpoints available at http://localhost:5001")
    print("POST /analyze - Analyze single password")
    print("POST /batch-analyze - Analyze multiple passwords")
    print("GET /policy-check - Get current policy requirements")
    print("GET /health - Health check")

    analyzer.run()