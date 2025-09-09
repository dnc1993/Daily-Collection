// Enhanced Access Control System with Multiple Passwords

// Password configuration for different access levels
const ACCESS_PASSWORDS = {
    borrower: "borrower123",      // For borrower summary
    analysis: "analysis456",      // For analysis page
    weekly: "weekly789",          // For weekly payments
    newloan: "loan101",           // For new loan page
    admin: "admin999"             // For full admin access
};

// Check authentication for specific access level
function isAuthenticatedFor(level) {
    const authKey = `${level}_authenticated`;
    const timeKey = `${level}_auth_time`;
    const isAuthenticated = sessionStorage.getItem(authKey);
    const authTime = sessionStorage.getItem(timeKey);
    const currentTime = Date.now();

    // Check if authentication is expired (30 minutes)
    if (authTime && (currentTime - parseInt(authTime)) > 30 * 60 * 1000) {
        sessionStorage.removeItem(authKey);
        sessionStorage.removeItem(timeKey);
        sessionStorage.removeItem('user_role');
        return false;
    }

    return isAuthenticated === 'true';
}

// Authenticate with specific password
function authenticateFor(level, password) {
    if (password === ACCESS_PASSWORDS[level]) {
        const authKey = `${level}_authenticated`;
        const timeKey = `${level}_auth_time`;

        sessionStorage.setItem(authKey, 'true');
        sessionStorage.setItem(timeKey, Date.now().toString());
        sessionStorage.setItem('user_role', level);
        return true;
    }
    return false;
}

// Check if user is admin (from JWT token)
function isAdminAuthenticated() {
    const token = localStorage.getItem('auth_token');
    if (!token) return false;

    try {
        // Decode JWT token to check role (simple decode, not secure for production)
        const payload = JSON.parse(atob(token.split('.')[1]));
        return payload.role === 'superadmin' || payload.role === 'admin';
    } catch (e) {
        return false;
    }
}

// Legacy function for backward compatibility
function isBorrowerAuthenticated() {
    return isAuthenticatedFor('borrower');
}

// Get user role (prioritizes admin over other authentications)
function getUserRole() {
    if (isAdminAuthenticated()) return 'admin';

    // Check for other authentications
    for (const level of Object.keys(ACCESS_PASSWORDS)) {
        if (isAuthenticatedFor(level)) {
            return level;
        }
    }

    return 'guest';
}

// Restrict access based on user role
function restrictAccess(allowedRoles = []) {
    const userRole = getUserRole();

    if (!allowedRoles.includes(userRole)) {
        if (userRole === 'borrower') {
            // Borrower trying to access admin page - redirect to borrower summary
            window.location.href = '/borrower_summary.html';
        } else if (userRole === 'admin') {
            // Admin trying to access borrower page - redirect to dashboard
            window.location.href = '/';
        } else {
            // Guest user - redirect to login
            window.location.href = '/login.html';
        }
        return false;
    }
    return true;
}

// Borrower-specific access control
function requireBorrowerAccess() {
    return restrictAccess(['borrower']);
}

// Admin-specific access control
function requireAdminAccess() {
    return restrictAccess(['admin']);
}

// Logout specific authentication level
function logoutLevel(level) {
    sessionStorage.removeItem(`${level}_authenticated`);
    sessionStorage.removeItem(`${level}_auth_time`);
    sessionStorage.removeItem('user_role');

    // Redirect based on level
    if (level === 'borrower') {
        window.location.href = '/borrower_summary.html';
    } else {
        window.location.href = '/';
    }
}

// Legacy function for backward compatibility
function logoutBorrower() {
    logoutLevel('borrower');
}

// Logout admin
function logoutAdmin() {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_info');
    window.location.href = '/login.html';
}

// Show authentication modal for specific access level
function showAuthModal(level) {
    const modal = document.createElement('div');
    modal.innerHTML = `
        <div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 9999; display: flex; align-items: center; justify-content: center;">
            <div style="background: white; padding: 30px; border-radius: 10px; width: 90%; max-width: 400px; text-align: center;">
                <h2 style="color: #2c3e50; margin-bottom: 20px;">${level.charAt(0).toUpperCase() + level.slice(1)} Access</h2>
                <p style="color: #666; margin-bottom: 20px;">Enter password to access this page</p>
                <input type="password" id="auth-password" placeholder="Enter password" style="width: 100%; padding: 12px; margin-bottom: 15px; border: 2px solid #ddd; border-radius: 5px; font-size: 16px;">
                <div id="auth-error" style="color: #e74c3c; margin-bottom: 15px; display: none;"></div>
                <button onclick="authenticateUser('${level}')" style="background: #3498db; color: white; border: none; padding: 12px 30px; border-radius: 5px; font-size: 16px; cursor: pointer; width: 100%;">Access Page</button>
                <button onclick="goToHome()" style="background: #95a5a6; color: white; border: none; padding: 10px 20px; border-radius: 5px; font-size: 14px; cursor: pointer; margin-top: 10px;">Back to Home</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    document.getElementById('auth-password').focus();
}

// Authenticate user for specific level
function authenticateUser(level) {
    const password = document.getElementById('auth-password').value;
    const errorDiv = document.getElementById('auth-error');

    if (authenticateFor(level, password)) {
        location.reload(); // Reload to show the main content
    } else {
        errorDiv.textContent = 'Incorrect password. Please try again.';
        errorDiv.style.display = 'block';
        document.getElementById('auth-password').value = '';
        document.getElementById('auth-password').focus();
    }
}

// Redirect to home
function goToHome() {
    window.location.href = '/';
}

// Auto-redirect users who try to access restricted pages
document.addEventListener('DOMContentLoaded', function() {
    const currentPath = window.location.pathname;

    // Define page access requirements
    const pageAccess = {
        '/administrator.html': ['admin'],
        '/newloan.html': ['admin', 'newloan'],
        '/analysis.html': ['admin', 'analysis'],
        '/weekly.html': ['admin', 'weekly'],
        '/borrower_summary.html': ['borrower']
    };

    // Check if current page requires specific access
    for (const [page, allowedRoles] of Object.entries(pageAccess)) {
        if (currentPath.includes(page)) {
            const userRole = getUserRole();
            if (!allowedRoles.includes(userRole)) {
                // Show authentication modal for the first allowed role
                showAuthModal(allowedRoles[0]);
            }
            break;
        }
    }
});