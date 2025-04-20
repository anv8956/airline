// Authentication utilities
class AuthHelper {
    // Simple SHA-256 hashing (for demonstration)
    static async hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Store user session
    static storeSession(user) {
        const sessionData = {
            username: user.username,
            name: user.name,
            role: user.role,
            expires: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
        };
        localStorage.setItem('currentSession', JSON.stringify(sessionData));
    }

    // Check for existing session
    static checkSession() {
        const session = localStorage.getItem('currentSession');
        if (!session) return null;
        
        const sessionData = JSON.parse(session);
        if (sessionData.expires < Date.now()) {
            localStorage.removeItem('currentSession');
            return null;
        }
        return sessionData;
    }

    // Clear session
    static clearSession() {
        localStorage.removeItem('currentSession');
    }

    // Validate email format
    static validateEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }

    // Check password strength
    static checkPasswordStrength(password) {
        const hasMinLength = password.length >= 8;
        const hasNumber = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);

        return {
            hasMinLength,
            hasNumber,
            hasSpecialChar,
            hasUpper,
            hasLower,
            strengthScore: [hasMinLength, hasNumber, hasSpecialChar, hasUpper, hasLower]
                .filter(Boolean).length
        };
    }
}

// Remember Me functionality
class RememberMe {
    static STORAGE_KEY = 'rememberedUser';

    static rememberUser(username) {
        localStorage.setItem(this.STORAGE_KEY, username);
    }

    static getRememberedUser() {
        return localStorage.getItem(this.STORAGE_KEY);
    }

    static forgetUser() {
        localStorage.removeItem(this.STORAGE_KEY);
    }
}

// Form validation utilities
class FormValidator {
    static showError(element, message) {
        const errorElement = document.getElementById(`${element.id}-error`);
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';
        }
    }

    static hideError(element) {
        const errorElement = document.getElementById(`${element.id}-error`);
        if (errorElement) {
            errorElement.style.display = 'none';
        }
    }

    static validateField(element, rules) {
        const value = element.value.trim();
        let isValid = true;

        if (rules.required && !value) {
            this.showError(element, 'This field is required');
            isValid = false;
        }

        if (rules.email && value && !AuthHelper.validateEmail(value)) {
            this.showError(element, 'Please enter a valid email');
            isValid = false;
        }

        if (rules.minLength && value.length < rules.minLength) {
            this.showError(element, `Minimum ${rules.minLength} characters required`);
            isValid = false;
        }

        if (isValid) {
            this.hideError(element);
        }

        return isValid;
    }
}

// Export for use in other files
export { AuthHelper, RememberMe, FormValidator };
