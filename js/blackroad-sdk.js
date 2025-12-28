/**
 * BlackRoad OS - Frontend SDK
 * Connects static HTML pages to the backend API
 */

(function() {
    'use strict';

    // Configuration
    const CONFIG = {
        API_URL: window.BLACKROAD_API_URL || 'https://api.blackroad.io',
        STORAGE_PREFIX: 'blackroad_'
    };

    // ===========================================
    // TOKEN MANAGEMENT
    // ===========================================

    const TokenManager = {
        getAccessToken() {
            return localStorage.getItem(CONFIG.STORAGE_PREFIX + 'access_token');
        },

        getRefreshToken() {
            return localStorage.getItem(CONFIG.STORAGE_PREFIX + 'refresh_token');
        },

        setTokens(access, refresh) {
            localStorage.setItem(CONFIG.STORAGE_PREFIX + 'access_token', access);
            if (refresh) {
                localStorage.setItem(CONFIG.STORAGE_PREFIX + 'refresh_token', refresh);
            }
        },

        clearTokens() {
            localStorage.removeItem(CONFIG.STORAGE_PREFIX + 'access_token');
            localStorage.removeItem(CONFIG.STORAGE_PREFIX + 'refresh_token');
            localStorage.removeItem(CONFIG.STORAGE_PREFIX + 'user');
        },

        getUser() {
            const userData = localStorage.getItem(CONFIG.STORAGE_PREFIX + 'user');
            return userData ? JSON.parse(userData) : null;
        },

        setUser(user) {
            localStorage.setItem(CONFIG.STORAGE_PREFIX + 'user', JSON.stringify(user));
        },

        isLoggedIn() {
            return !!this.getAccessToken();
        }
    };

    // ===========================================
    // API CLIENT
    // ===========================================

    const API = {
        async request(endpoint, options = {}) {
            const url = CONFIG.API_URL + endpoint;
            const headers = {
                'Content-Type': 'application/json',
                ...options.headers
            };

            const token = TokenManager.getAccessToken();
            if (token) {
                headers['Authorization'] = 'Bearer ' + token;
            }

            try {
                const response = await fetch(url, {
                    ...options,
                    headers
                });

                // Handle token refresh
                if (response.status === 401 && TokenManager.getRefreshToken()) {
                    const refreshed = await this.refreshToken();
                    if (refreshed) {
                        headers['Authorization'] = 'Bearer ' + TokenManager.getAccessToken();
                        return fetch(url, { ...options, headers });
                    }
                }

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || 'Request failed');
                }

                return data;
            } catch (error) {
                console.error('API Error:', error);
                throw error;
            }
        },

        async refreshToken() {
            try {
                const response = await fetch(CONFIG.API_URL + '/api/auth/refresh', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + TokenManager.getRefreshToken()
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    TokenManager.setTokens(data.access_token);
                    return true;
                }
            } catch (error) {
                console.error('Token refresh failed:', error);
            }

            TokenManager.clearTokens();
            return false;
        },

        // Auth endpoints
        async register(email, password, name) {
            const data = await this.request('/api/auth/register', {
                method: 'POST',
                body: JSON.stringify({ email, password, name })
            });
            TokenManager.setTokens(data.access_token, data.refresh_token);
            TokenManager.setUser(data.user);
            return data;
        },

        async login(email, password) {
            const data = await this.request('/api/auth/login', {
                method: 'POST',
                body: JSON.stringify({ email, password })
            });
            TokenManager.setTokens(data.access_token, data.refresh_token);
            TokenManager.setUser(data.user);
            return data;
        },

        async logout() {
            TokenManager.clearTokens();
            window.location.href = '/';
        },

        async getCurrentUser() {
            return this.request('/api/auth/me');
        },

        async updateProfile(data) {
            return this.request('/api/auth/update', {
                method: 'PUT',
                body: JSON.stringify(data)
            });
        },

        // Dashboard endpoints
        async getDashboardStats() {
            return this.request('/api/dashboard/stats');
        },

        async getUsageStats() {
            return this.request('/api/dashboard/usage');
        },

        // Form endpoints
        async subscribeNewsletter(email, name, source) {
            return this.request('/api/newsletter/subscribe', {
                method: 'POST',
                body: JSON.stringify({ email, name, source })
            });
        },

        async submitContact(name, email, message, company, type) {
            return this.request('/api/contact', {
                method: 'POST',
                body: JSON.stringify({ name, email, message, company, type })
            });
        },

        async signupAffiliate(name, email, website, socialLinks) {
            return this.request('/api/affiliate/signup', {
                method: 'POST',
                body: JSON.stringify({ name, email, website, social_links: socialLinks })
            });
        }
    };

    // ===========================================
    // UI HELPERS
    // ===========================================

    const UI = {
        showNotification(message, type = 'success') {
            // Remove existing notifications
            const existing = document.querySelector('.br-notification');
            if (existing) existing.remove();

            const notification = document.createElement('div');
            notification.className = 'br-notification br-notification-' + type;
            notification.innerHTML = `
                <span>${message}</span>
                <button onclick="this.parentElement.remove()">&times;</button>
            `;
            document.body.appendChild(notification);

            // Auto-remove after 5 seconds
            setTimeout(() => notification.remove(), 5000);
        },

        showLoading(element) {
            element.dataset.originalText = element.innerHTML;
            element.innerHTML = '<span class="br-spinner"></span> Loading...';
            element.disabled = true;
        },

        hideLoading(element) {
            element.innerHTML = element.dataset.originalText || element.innerHTML;
            element.disabled = false;
        },

        updateAuthUI() {
            const isLoggedIn = TokenManager.isLoggedIn();
            const user = TokenManager.getUser();

            // Update auth buttons
            document.querySelectorAll('[data-auth="logged-out"]').forEach(el => {
                el.style.display = isLoggedIn ? 'none' : '';
            });

            document.querySelectorAll('[data-auth="logged-in"]').forEach(el => {
                el.style.display = isLoggedIn ? '' : 'none';
            });

            // Update user name displays
            if (user) {
                document.querySelectorAll('[data-user="name"]').forEach(el => {
                    el.textContent = user.name || user.email;
                });
                document.querySelectorAll('[data-user="email"]').forEach(el => {
                    el.textContent = user.email;
                });
                document.querySelectorAll('[data-user="tier"]').forEach(el => {
                    el.textContent = user.subscription_tier;
                });
            }
        }
    };

    // ===========================================
    // FORM HANDLERS
    // ===========================================

    const FormHandlers = {
        init() {
            // Newsletter forms
            document.querySelectorAll('[data-form="newsletter"]').forEach(form => {
                form.addEventListener('submit', this.handleNewsletter.bind(this));
            });

            // Contact forms
            document.querySelectorAll('[data-form="contact"]').forEach(form => {
                form.addEventListener('submit', this.handleContact.bind(this));
            });

            // Affiliate signup forms
            document.querySelectorAll('[data-form="affiliate"]').forEach(form => {
                form.addEventListener('submit', this.handleAffiliate.bind(this));
            });

            // Login forms
            document.querySelectorAll('[data-form="login"]').forEach(form => {
                form.addEventListener('submit', this.handleLogin.bind(this));
            });

            // Register forms
            document.querySelectorAll('[data-form="register"]').forEach(form => {
                form.addEventListener('submit', this.handleRegister.bind(this));
            });

            // Logout buttons
            document.querySelectorAll('[data-action="logout"]').forEach(btn => {
                btn.addEventListener('click', () => API.logout());
            });

            // Calculator form
            document.querySelectorAll('[data-form="calculator"]').forEach(form => {
                form.addEventListener('submit', this.handleCalculator.bind(this));
            });
        },

        async handleNewsletter(e) {
            e.preventDefault();
            const form = e.target;
            const button = form.querySelector('button[type="submit"]');
            const email = form.querySelector('[name="email"]').value;
            const name = form.querySelector('[name="name"]')?.value || '';
            const source = form.dataset.source || 'website';

            try {
                UI.showLoading(button);
                await API.subscribeNewsletter(email, name, source);
                UI.showNotification('Successfully subscribed! Check your email.', 'success');
                form.reset();
            } catch (error) {
                UI.showNotification(error.message || 'Subscription failed', 'error');
            } finally {
                UI.hideLoading(button);
            }
        },

        async handleContact(e) {
            e.preventDefault();
            const form = e.target;
            const button = form.querySelector('button[type="submit"]');

            const data = {
                name: form.querySelector('[name="name"]').value,
                email: form.querySelector('[name="email"]').value,
                message: form.querySelector('[name="message"]').value,
                company: form.querySelector('[name="company"]')?.value || '',
                type: form.dataset.type || 'general'
            };

            try {
                UI.showLoading(button);
                await API.submitContact(data.name, data.email, data.message, data.company, data.type);
                UI.showNotification('Message sent! We\'ll get back to you soon.', 'success');
                form.reset();
            } catch (error) {
                UI.showNotification(error.message || 'Failed to send message', 'error');
            } finally {
                UI.hideLoading(button);
            }
        },

        async handleAffiliate(e) {
            e.preventDefault();
            const form = e.target;
            const button = form.querySelector('button[type="submit"]');

            const data = {
                name: form.querySelector('[name="name"]').value,
                email: form.querySelector('[name="email"]').value,
                website: form.querySelector('[name="website"]')?.value || '',
                socialLinks: {
                    twitter: form.querySelector('[name="twitter"]')?.value || '',
                    linkedin: form.querySelector('[name="linkedin"]')?.value || ''
                }
            };

            try {
                UI.showLoading(button);
                const result = await API.signupAffiliate(data.name, data.email, data.website, data.socialLinks);
                UI.showNotification(`Application submitted! Your referral code: ${result.referral_code}`, 'success');
                form.reset();
            } catch (error) {
                UI.showNotification(error.message || 'Signup failed', 'error');
            } finally {
                UI.hideLoading(button);
            }
        },

        async handleLogin(e) {
            e.preventDefault();
            const form = e.target;
            const button = form.querySelector('button[type="submit"]');

            const email = form.querySelector('[name="email"]').value;
            const password = form.querySelector('[name="password"]').value;

            try {
                UI.showLoading(button);
                await API.login(email, password);
                UI.showNotification('Login successful!', 'success');
                UI.updateAuthUI();
                window.location.href = '/dashboard.html';
            } catch (error) {
                UI.showNotification(error.message || 'Login failed', 'error');
            } finally {
                UI.hideLoading(button);
            }
        },

        async handleRegister(e) {
            e.preventDefault();
            const form = e.target;
            const button = form.querySelector('button[type="submit"]');

            const name = form.querySelector('[name="name"]')?.value || '';
            const email = form.querySelector('[name="email"]').value;
            const password = form.querySelector('[name="password"]').value;

            try {
                UI.showLoading(button);
                await API.register(email, password, name);
                UI.showNotification('Account created!', 'success');
                UI.updateAuthUI();
                window.location.href = '/dashboard.html';
            } catch (error) {
                UI.showNotification(error.message || 'Registration failed', 'error');
            } finally {
                UI.hideLoading(button);
            }
        },

        handleCalculator(e) {
            e.preventDefault();
            const form = e.target;

            const teamSize = parseInt(form.querySelector('[name="teamSize"]')?.value) || 5;
            const deployFreq = parseInt(form.querySelector('[name="deployFreq"]')?.value) || 10;
            const hourlyRate = parseInt(form.querySelector('[name="hourlyRate"]')?.value) || 100;

            // Calculate savings
            const hoursPerDeployWithout = 2;
            const hoursPerDeployWith = 0.25;
            const hoursSaved = (hoursPerDeployWithout - hoursPerDeployWith) * deployFreq;
            const monthlySavings = hoursSaved * hourlyRate;
            const yearlySavings = monthlySavings * 12;
            const blackroadCost = 29 * 12; // Founding member price
            const netSavings = yearlySavings - blackroadCost;
            const roi = Math.round((netSavings / blackroadCost) * 100);

            // Display results
            const resultsEl = document.querySelector('[data-calculator="results"]');
            if (resultsEl) {
                resultsEl.innerHTML = `
                    <div class="calc-result">
                        <h3>Your Potential Savings</h3>
                        <div class="result-grid">
                            <div class="result-item">
                                <span class="result-label">Hours Saved/Month</span>
                                <span class="result-value">${hoursSaved.toFixed(1)}</span>
                            </div>
                            <div class="result-item">
                                <span class="result-label">Monthly Savings</span>
                                <span class="result-value">$${monthlySavings.toLocaleString()}</span>
                            </div>
                            <div class="result-item">
                                <span class="result-label">Yearly Savings</span>
                                <span class="result-value">$${yearlySavings.toLocaleString()}</span>
                            </div>
                            <div class="result-item highlight">
                                <span class="result-label">ROI</span>
                                <span class="result-value">${roi}%</span>
                            </div>
                        </div>
                        <p class="result-cta">Start saving now with BlackRoad OS</p>
                        <a href="https://buy.stripe.com/9B6cN4fOr6bYbvi8xD" class="button">Start Free Trial</a>
                    </div>
                `;
                resultsEl.style.display = 'block';
            }
        }
    };

    // ===========================================
    // DASHBOARD
    // ===========================================

    const Dashboard = {
        async init() {
            if (!document.querySelector('[data-page="dashboard"]')) return;

            if (!TokenManager.isLoggedIn()) {
                window.location.href = '/login.html';
                return;
            }

            try {
                const stats = await API.getDashboardStats();
                this.render(stats);
            } catch (error) {
                console.error('Failed to load dashboard:', error);
                UI.showNotification('Failed to load dashboard data', 'error');
            }
        },

        render(data) {
            // Update stat cards
            document.querySelectorAll('[data-stat]').forEach(el => {
                const stat = el.dataset.stat;
                if (data.stats[stat] !== undefined) {
                    el.textContent = data.stats[stat];
                }
            });

            // Update user info
            if (data.user) {
                document.querySelectorAll('[data-user="name"]').forEach(el => {
                    el.textContent = data.user.name || data.user.email;
                });
                document.querySelectorAll('[data-user="tier"]').forEach(el => {
                    el.textContent = data.user.subscription_tier.toUpperCase();
                });
            }

            // Render activity feed
            const activityFeed = document.querySelector('[data-dashboard="activity"]');
            if (activityFeed && data.recent_activity) {
                activityFeed.innerHTML = data.recent_activity.map(event => `
                    <div class="activity-item">
                        <span class="activity-type">${event.event_type}</span>
                        <span class="activity-time">${new Date(event.created_at).toLocaleDateString()}</span>
                    </div>
                `).join('');
            }
        }
    };

    // ===========================================
    // FAQ ACCORDION
    // ===========================================

    const FAQ = {
        init() {
            document.querySelectorAll('.faq-item').forEach(item => {
                const question = item.querySelector('.faq-question');
                const answer = item.querySelector('.faq-answer');

                if (question && answer) {
                    question.addEventListener('click', () => {
                        const isOpen = item.classList.contains('active');

                        // Close all others
                        document.querySelectorAll('.faq-item.active').forEach(other => {
                            other.classList.remove('active');
                        });

                        // Toggle current
                        if (!isOpen) {
                            item.classList.add('active');
                        }
                    });
                }
            });
        }
    };

    // ===========================================
    // NOTIFICATION STYLES
    // ===========================================

    const injectStyles = () => {
        const style = document.createElement('style');
        style.textContent = `
            .br-notification {
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 15px 20px;
                border-radius: 10px;
                color: white;
                font-weight: 600;
                display: flex;
                align-items: center;
                gap: 15px;
                z-index: 10000;
                animation: slideIn 0.3s ease;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            }
            .br-notification-success {
                background: linear-gradient(135deg, #10b981, #059669);
            }
            .br-notification-error {
                background: linear-gradient(135deg, #ef4444, #dc2626);
            }
            .br-notification button {
                background: none;
                border: none;
                color: white;
                font-size: 20px;
                cursor: pointer;
                opacity: 0.8;
            }
            .br-notification button:hover {
                opacity: 1;
            }
            .br-spinner {
                display: inline-block;
                width: 16px;
                height: 16px;
                border: 2px solid rgba(255,255,255,0.3);
                border-radius: 50%;
                border-top-color: white;
                animation: spin 0.8s linear infinite;
            }
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
        `;
        document.head.appendChild(style);
    };

    // ===========================================
    // INITIALIZATION
    // ===========================================

    const init = () => {
        injectStyles();
        FormHandlers.init();
        FAQ.init();
        Dashboard.init();
        UI.updateAuthUI();

        // Analytics tracking (placeholder)
        window.BlackRoad = {
            API,
            TokenManager,
            UI,
            track: (event, data) => {
                console.log('[Analytics]', event, data);
                // Integrate with Mixpanel, GA, etc.
            }
        };

        console.log('🚀 BlackRoad SDK initialized');
    };

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
