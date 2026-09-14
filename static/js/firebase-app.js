/**
 * ieWebNative - Unified Firebase Client Service
 * Supports Firebase Authentication (Email/Password, Google Sign-In, Password Reset),
 * Cloud Firestore, and Cloud Storage with automatic fallback to local backend APIs.
 */

(function (window) {
    'use strict';

    class FirebaseService {
        constructor() {
            this.app = null;
            this.auth = null;
            this.db = null;
            this.storage = null;
            this.configured = false;
            this.config = null;
            this._initPromise = null;
        }

        /**
         * Normalizes config keys (handles snake_case and camelCase)
         */
        _normalizeConfig(rawConfig) {
            if (!rawConfig || typeof rawConfig !== 'object') return null;
            const apiKey = rawConfig.apiKey || rawConfig.api_key || '';
            const authDomain = rawConfig.authDomain || rawConfig.auth_domain || '';
            const projectId = rawConfig.projectId || rawConfig.project_id || '';
            const storageBucket = rawConfig.storageBucket || rawConfig.storage_bucket || '';
            const messagingSenderId = rawConfig.messagingSenderId || rawConfig.messaging_sender_id || '';
            const appId = rawConfig.appId || rawConfig.app_id || '';
            const measurementId = rawConfig.measurementId || rawConfig.measurement_id || '';

            // Check if valid credentials are provided (not empty and not placeholder)
            if (!apiKey || apiKey.includes('YOUR_') || !projectId || projectId.includes('YOUR_')) {
                return null;
            }

            return {
                apiKey,
                authDomain,
                projectId,
                storageBucket,
                messagingSenderId,
                appId,
                measurementId
            };
        }

        /**
         * Dynamically load Firebase SDK compat scripts if not already in DOM
         */
        async loadScripts() {
            if (window.firebase) return true;

            const scripts = [
                'https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js',
                'https://www.gstatic.com/firebasejs/10.12.2/firebase-auth-compat.js',
                'https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore-compat.js',
                'https://www.gstatic.com/firebasejs/10.12.2/firebase-storage-compat.js'
            ];

            const loadScript = (url) => {
                return new Promise((resolve, reject) => {
                    const existing = document.querySelector(`script[src="${url}"]`);
                    if (existing) {
                        if (existing.dataset.loaded === 'true') return resolve();
                        existing.addEventListener('load', () => resolve());
                        existing.addEventListener('error', (err) => reject(err));
                        return;
                    }
                    const script = document.createElement('script');
                    script.src = url;
                    script.async = false; // Preserve loading order
                    script.onload = () => {
                        script.dataset.loaded = 'true';
                        resolve();
                    };
                    script.onerror = (err) => reject(err);
                    document.head.appendChild(script);
                });
            };

            for (const src of scripts) {
                try {
                    await loadScript(src);
                } catch (e) {
                    console.warn('[Firebase] Could not load SDK from CDN:', src, e);
                    return false;
                }
            }
            return !!window.firebase;
        }

        /**
         * Initialize Firebase service with configuration
         */
        async init(configInput) {
            if (this._initPromise) return this._initPromise;

            this._initPromise = (async () => {
                let rawConfig = configInput || window.FIREBASE_CONFIG;

                // If not provided, fetch from backend endpoint
                if (!rawConfig) {
                    try {
                        const res = await fetch('/api/firebase-config');
                        if (res.ok) {
                            const data = await res.json();
                            rawConfig = data.config || data;
                        }
                    } catch (err) {
                        console.debug('[Firebase] Could not fetch server config:', err);
                    }
                }

                const normalized = this._normalizeConfig(rawConfig);
                if (!normalized) {
                    this.configured = false;
                    console.log('[Firebase] Running in Local SQLite & Storage mode (Firebase keys not configured).');
                    return false;
                }

                this.config = normalized;

                // Ensure SDK scripts are available
                const scriptsLoaded = await this.loadScripts();
                if (!scriptsLoaded || !window.firebase) {
                    console.warn('[Firebase] SDK unavailable. Falling back to local mode.');
                    this.configured = false;
                    return false;
                }

                try {
                    if (!window.firebase.apps.length) {
                        this.app = window.firebase.initializeApp(this.config);
                    } else {
                        this.app = window.firebase.app();
                    }

                    this.auth = window.firebase.auth();
                    this.db = window.firebase.firestore();
                    this.storage = window.firebase.storage();
                    this.configured = true;
                    console.log('[Firebase] Initialized successfully with project:', this.config.projectId);
                    return true;
                } catch (e) {
                    console.warn('[Firebase] Initialization failed:', e);
                    this.configured = false;
                    return false;
                }
            })();

            return this._initPromise;
        }

        /**
         * Whether Firebase is fully active and configured with valid keys
         */
        isConfigured() {
            return this.configured && this.auth !== null;
        }

        /**
         * Synchronize Firebase ID token with backend session
         */
        async syncSessionWithBackend(idToken) {
            const response = await fetch('/api/auth/firebase-session', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${idToken}`
                },
                body: JSON.stringify({ idToken })
            });

            const result = await response.json();
            if (!response.ok || !result.success) {
                throw new Error(result.error || 'Failed to establish server session with Firebase.');
            }
            return result;
        }

        /**
         * Sign in with Google Popup
         */
        async signInWithGoogle() {
            await this.init();
            if (!this.isConfigured()) {
                throw new Error('Firebase Authentication is not configured. Please add your Firebase API keys to .env');
            }

            const provider = new window.firebase.auth.GoogleAuthProvider();
            provider.setCustomParameters({ prompt: 'select_account' });

            const userCredential = await this.auth.signInWithPopup(provider);
            const idToken = await userCredential.user.getIdToken();
            const sessionResult = await this.syncSessionWithBackend(idToken);
            return {
                user: userCredential.user,
                session: sessionResult
            };
        }

        /**
         * Sign in with Email and Password
         */
        async signInWithEmail(email, password) {
            await this.init();
            if (!this.isConfigured()) {
                // Fallback to local SQLite login
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const result = await response.json();
                if (!response.ok || !result.success) {
                    throw new Error(result.error || 'Invalid credentials');
                }
                return { session: result };
            }

            const userCredential = await this.auth.signInWithEmailAndPassword(email, password);
            const idToken = await userCredential.user.getIdToken();
            const sessionResult = await this.syncSessionWithBackend(idToken);
            return {
                user: userCredential.user,
                session: sessionResult
            };
        }

        /**
         * Sign up with Email, Password and Display Name
         */
        async signUpWithEmail(email, password, displayName) {
            await this.init();
            if (!this.isConfigured()) {
                // Fallback to local SQLite signup
                const response = await fetch('/api/auth/signup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: displayName, email, password })
                });
                const result = await response.json();
                if (!response.ok || !result.success) {
                    throw new Error(result.error || 'Registration failed');
                }
                return { session: result };
            }

            const userCredential = await this.auth.createUserWithEmailAndPassword(email, password);
            if (displayName && userCredential.user) {
                await userCredential.user.updateProfile({ displayName: displayName });
            }
            const idToken = await userCredential.user.getIdToken(true);
            const sessionResult = await this.syncSessionWithBackend(idToken);
            return {
                user: userCredential.user,
                session: sessionResult
            };
        }

        /**
         * Send Password Reset Email
         */
        async resetPassword(email) {
            await this.init();
            if (this.isConfigured()) {
                await this.auth.sendPasswordResetEmail(email);
                return { success: true };
            } else {
                // Return success message for local development mode
                return { success: true, localMode: true };
            }
        }

        /**
         * Sign out from both Firebase and backend session
         */
        async signOut() {
            try {
                if (this.auth) {
                    await this.auth.signOut();
                }
            } catch (err) {
                console.warn('[Firebase] Auth sign-out error:', err);
            }

            try {
                await fetch('/api/auth/logout', { method: 'POST' });
            } catch (err) {
                console.warn('[Firebase] Session logout error:', err);
            }

            window.location.href = '/';
        }

        /**
         * Upload file to Firebase Cloud Storage, falling back to local upload endpoint
         */
        async uploadFile(file, storagePath) {
            await this.init();

            // 1. Try Firebase Storage if configured
            if (this.isConfigured() && this.storage && this.config.storageBucket) {
                try {
                    const storageRef = this.storage.ref(storagePath);
                    const snapshot = await storageRef.put(file);
                    const downloadUrl = await snapshot.ref.getDownloadURL();
                    return downloadUrl;
                } catch (e) {
                    console.warn('[Firebase] Direct storage upload failed, falling back to server upload:', e);
                }
            }

            // 2. Fallback to server /api/storage/upload endpoint
            const formData = new FormData();
            formData.append('file', file);
            formData.append('path', storagePath);

            const res = await fetch('/api/storage/upload', {
                method: 'POST',
                body: formData
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.error || 'Failed to upload asset');
            }

            const data = await res.json();
            return data.url || data.downloadUrl;
        }

        /**
         * Auth state observer
         */
        onAuthStateChanged(callback) {
            if (this.auth) {
                return this.auth.onAuthStateChanged(callback);
            }
            return () => {};
        }
    }

    // Export singleton instance to window
    window.FirebaseAppService = new FirebaseService();

    // Auto-initialize if window.FIREBASE_CONFIG is present
    if (window.FIREBASE_CONFIG) {
        window.FirebaseAppService.init(window.FIREBASE_CONFIG).catch(err => {
            console.debug('[Firebase] Auto-init:', err);
        });
    }

})(window);
