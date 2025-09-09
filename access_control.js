// Access Control System for Borrower Portal

// Check if user is authenticated as borrower
function isBorrowerAuthenticated() {
    const isAuthenticated = sessionStorage.getItem('borrower_authenticated');
    const authTime = sessionStorage.getItem('borrower_auth_time');
    const currentTime = Date.now();

    // Check if authentication is expired (30 minutes)
    if (authTime && (currentTime - parseInt(authTime)) > 30 * 60 * 1000) {
        sessionStorage.removeItem('borrower_authenticated');
        sessionStorage.removeItem('borrower_auth_time');
        sessionStorage.removeItem('user_role');
        return false;
    }

    return isAuthenticated === 'true';
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

// Get user role
function getUserRole() {
    if (isAdminAuthenticated()) return 'admin';
    if (isBorrowerAuthenticated()) return 'borrower';
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

// Logout borrower
function logoutBorrower() {
    sessionStorage.removeItem('borrower_authenticated');
    sessionStorage.removeItem('borrower_auth_time');
    sessionStorage.removeItem('user_role');
    window.location.href = '/borrower_summary.html';
}

// Logout admin
function logoutAdmin() {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_info');
    window.location.href = '/login.html';
}

// Auto-redirect borrowers who try to access admin pages
document.addEventListener('DOMContentLoaded', function() {
    const currentPath = window.location.pathname;

    // If on admin pages, require admin access
    if (currentPath.includes('/administrator.html') ||
        currentPath.includes('/newloan.html') ||
        currentPath.includes('/analysis.html') ||
        currentPath.includes('/weekly.html')) {
        requireAdminAccess();
    }

    // If on borrower summary, require borrower access
    if (currentPath.includes('/borrower_summary.html')) {
        requireBorrowerAccess();
    }
});