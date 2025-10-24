import math
import string

def check_password_strength(password):
    result = {
        'length': len(password),
        'has_lower': any(c.islower() for c in password),
        'has_upper': any(c.isupper() for c in password),
        'has_digit': any(c.isdigit() for c in password),
        'has_symbol': any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password),
        'entropy': 0.0,
        'level': '',
        'suggestions': []
    }
    
    pool_size = _calculate_pool_size(result)
    result['entropy'] = _calculate_entropy(len(password), pool_size)
    
    score = _calculate_score(result)
    result['level'] = _get_strength_level(score)
    
    result['suggestions'] = _generate_suggestions(result)
    
    return result


def _calculate_pool_size(result):
    pool_size = 0
    
    if result['has_lower']:
        pool_size += 26
    if result['has_upper']:
        pool_size += 26
    if result['has_digit']:
        pool_size += 10
    if result['has_symbol']:
        pool_size += 32
    
    return pool_size


def _calculate_entropy(length, pool_size):
    if pool_size == 0:
        return 0.0
    
    return length * math.log2(pool_size)


def _calculate_score(result):
    score = 0
    
    if result['length'] >= 8:
        score += 10
    if result['length'] >= 12:
        score += 10
    if result['length'] >= 16:
        score += 10
    if result['length'] >= 20:
        score += 10
    
    if result['has_lower']:
        score += 10
    if result['has_upper']:
        score += 10
    if result['has_digit']:
        score += 10
    if result['has_symbol']:
        score += 15
    
    if result['entropy'] >= 60:
        score += 10
    if result['entropy'] >= 80:
        score += 10
    if result['entropy'] >= 100:
        score += 5
    
    return min(score, 100)


def _get_strength_level(score):
    if score >= 80:
        return "Very Strong"
    elif score >= 60:
        return "Strong"
    elif score >= 40:
        return "Medium"
    else:
        return "Weak"


def _generate_suggestions(result):
    suggestions = []
    
    if result['length'] < 12:
        suggestions.append("Increase length to at least 12 characters")
    elif result['length'] < 16:
        suggestions.append("Consider increasing length to 16+ characters for better security")
    
    if not result['has_upper']:
        suggestions.append("Add uppercase letters (A-Z)")
    
    if not result['has_lower']:
        suggestions.append("Add lowercase letters (a-z)")
    
    if not result['has_digit']:
        suggestions.append("Add numbers (0-9)")
    
    if not result['has_symbol']:
        suggestions.append("Add special symbols (!@#$%^&*...)")
    
    if result['entropy'] < 60:
        suggestions.append("Increase complexity for higher entropy")
    
    return suggestions
