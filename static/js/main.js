document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('build-form');
    const buildButton = document.getElementById('build-button');
    const buildProgress = document.getElementById('build-progress');
    const buildComplete = document.getElementById('build-complete');
    const progressFill = document.getElementById('progress-fill');
    const progressPercent = document.getElementById('progress-percent');
    const progressMessage = document.getElementById('progress-message');
    const downloadLinks = document.getElementById('download-links');
    const webUrlInput = document.getElementById('web-url');
    const previewIframe = document.getElementById('preview-iframe');
    const previewLoading = document.getElementById('preview-loading');
    const placeholderContent = document.getElementById('placeholder-content');

    if (previewIframe) {
        previewIframe.addEventListener('load', function() {
            if (previewLoading) previewLoading.style.display = 'none';
        });
        previewIframe.addEventListener('error', function() {
            if (previewLoading) previewLoading.style.display = 'none';
        });
    }
    const deviceFrame = document.getElementById('device-frame');
    const deviceButtons = document.querySelectorAll('.device-btn');
    const keystoreSection = document.getElementById('keystore-section');
    const platformSelect = document.getElementById('platform-select');
    const keystoreFile = document.getElementById('keystore-file');
    const keystoreDetails = document.getElementById('keystore-details');
    const keystoreUploadLabel = document.getElementById('keystore-upload-label');

    // Project save/open elements
    const saveProjectBtn = document.getElementById('save-project-btn');
    const openProjectBtn = document.getElementById('open-project-btn');
    const openProjectFile = document.getElementById('open-project-file');

    // Store paths for icon and keystore (set after upload)
    let currentIconPath = null;
    let currentKeystorePath = null;
    let activeBuildId = null;

    // Apple signing paths and info
    let currentAppleCertificatePath = null;
    let currentAppleProfilePath = null;
    let currentAppleProfileInfo = null;
    let isAppleSigningAvailable = false;

    // Store Publishing paths
    let currentPlayKeyPath = null;
    let currentAppStoreKeyPath = null;

    // Splash & Error screen branding paths
    let currentSplashImagePath = null;
    let currentErrorImagePath = null;

    // Center progress elements
    const centerProgress = document.getElementById('center-progress');
    const centerProgressFill = document.getElementById('center-progress-fill');
    const centerProgressText = document.getElementById('center-progress-text');
    const platformDropdownWrapper = document.querySelector('.platform-dropdown-wrapper');

    // Settings dialog elements
    const settingsBtn = document.getElementById('settings-btn');
    const settingsOverlay = document.getElementById('settings-overlay');
    const settingsClose = document.getElementById('settings-close');
    const settingsCancel = document.getElementById('settings-cancel');
    const settingsSave = document.getElementById('settings-save');

    // Icon upload elements
    const iconFile = document.getElementById('icon-file');
    const iconPreview = document.getElementById('icon-preview');
    const iconUploadLabel = document.getElementById('icon-upload-label');

    // Splash & Error screen elements
    const splashImageFile = document.getElementById('splash-image-file');
    const splashImagePreview = document.getElementById('splash-image-preview');
    const splashImageUploadLabel = document.getElementById('splash-image-upload-label');
    const errorImageFile = document.getElementById('error-image-file');
    const errorImagePreview = document.getElementById('error-image-preview');
    const errorImageUploadLabel = document.getElementById('error-image-upload-label');
    const enableSplashScreen = document.getElementById('enable-splash-screen');
    const splashScreenDetails = document.getElementById('splash-screen-details');
    const enableErrorPage = document.getElementById('enable-error-page');
    const errorPageDetails = document.getElementById('error-page-details');

    // Mapping between hidden form checkboxes and settings dialog checkboxes
    const settingsMapping = {
        'allow-zoom': 'setting-allow-zoom',
        'enable-javascript': 'setting-enable-javascript',
        'enable-dom-storage': 'setting-enable-dom-storage',
        'enable-geolocation': 'setting-enable-geolocation',
        'enable-pull-refresh': 'setting-enable-pull-refresh',
        'show-navigation': 'setting-show-navigation',
        'enable-file-access': 'setting-enable-file-access',
        'enable-cache': 'setting-enable-cache',
        'enable-media-autoplay': 'setting-enable-media-autoplay',
        'enable-camera': 'setting-enable-camera',
        'enable-microphone': 'setting-enable-microphone',
        'enable-ssl-pinning': 'setting-enable-ssl-pinning',
        'enable-biometrics': 'setting-enable-biometrics',
        'enable-app-lock': 'setting-enable-app-lock',
        'enable-secure-storage': 'setting-enable-secure-storage'
    };

    // Dynamic visibility for security configuration groups
    const settingSslPinning = document.getElementById('setting-enable-ssl-pinning');
    const sslPinningGroup = document.getElementById('ssl-pinning-group');
    if (settingSslPinning && sslPinningGroup) {
        settingSslPinning.addEventListener('change', function() {
            sslPinningGroup.style.display = this.checked ? 'block' : 'none';
        });
    }

    const settingAppLock = document.getElementById('setting-enable-app-lock');
    const appLockGroup = document.getElementById('app-lock-group');
    if (settingAppLock && appLockGroup) {
        settingAppLock.addEventListener('change', function() {
            appLockGroup.style.display = this.checked ? 'block' : 'none';
        });
    }

    // Settings dialog handlers
    settingsBtn.addEventListener('click', openSettingsDialog);
    settingsClose.addEventListener('click', closeSettingsDialog);
    settingsCancel.addEventListener('click', closeSettingsDialog);
    settingsSave.addEventListener('click', saveSettings);
    settingsOverlay.addEventListener('click', function(e) {
        if (e.target === settingsOverlay) {
            closeSettingsDialog();
        }
    });

    function openSettingsDialog() {
        // Sync dialog checkboxes with hidden form checkboxes
        for (const [formId, dialogId] of Object.entries(settingsMapping)) {
            const formCheckbox = document.getElementById(formId);
            const dialogCheckbox = document.getElementById(dialogId);
            if (formCheckbox && dialogCheckbox) {
                dialogCheckbox.checked = formCheckbox.checked;
            }
        }
        // Sync text inputs
        const sslPinsHidden = document.getElementById('ssl-pins');
        const sslPinsSetting = document.getElementById('setting-ssl-pins');
        if (sslPinsHidden && sslPinsSetting) {
            sslPinsSetting.value = sslPinsHidden.value;
        }
        const appLockPinHidden = document.getElementById('app-lock-pin');
        const appLockPinSetting = document.getElementById('setting-app-lock-pin');
        if (appLockPinHidden && appLockPinSetting) {
            appLockPinSetting.value = appLockPinHidden.value;
        }
        if (sslPinningGroup && settingSslPinning) {
            sslPinningGroup.style.display = settingSslPinning.checked ? 'block' : 'none';
        }
        if (appLockGroup && settingAppLock) {
            appLockGroup.style.display = settingAppLock.checked ? 'block' : 'none';
        }

        settingsOverlay.style.display = 'flex';
        document.body.style.overflow = 'hidden';
    }

    function closeSettingsDialog() {
        settingsOverlay.style.display = 'none';
        document.body.style.overflow = '';
    }

    function saveSettings() {
        // Sync hidden form checkboxes with dialog checkboxes
        for (const [formId, dialogId] of Object.entries(settingsMapping)) {
            const formCheckbox = document.getElementById(formId);
            const dialogCheckbox = document.getElementById(dialogId);
            if (formCheckbox && dialogCheckbox) {
                formCheckbox.checked = dialogCheckbox.checked;
            }
        }
        // Sync text inputs
        const sslPinsHidden = document.getElementById('ssl-pins');
        const sslPinsSetting = document.getElementById('setting-ssl-pins');
        if (sslPinsHidden && sslPinsSetting) {
            sslPinsHidden.value = sslPinsSetting.value;
        }
        const appLockPinHidden = document.getElementById('app-lock-pin');
        const appLockPinSetting = document.getElementById('setting-app-lock-pin');
        if (appLockPinHidden && appLockPinSetting) {
            appLockPinHidden.value = appLockPinSetting.value;
        }

        closeSettingsDialog();
        showToast('Settings saved', 'success');
    }

    // Close dialog on Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && settingsOverlay.style.display === 'flex') {
            closeSettingsDialog();
        }
    });

    // Apple signing elements
    const appleSigningSection = document.getElementById('apple-signing-section');
    const appleSigningNotice = document.getElementById('apple-signing-notice');
    const appleCertificateFile = document.getElementById('apple-certificate-file');
    const appleCertificateUploadLabel = document.getElementById('apple-certificate-upload-label');
    const appleCertificateDetails = document.getElementById('apple-certificate-details');
    const appleCertificatePassword = document.getElementById('apple-certificate-password');
    const certificateInfo = document.getElementById('certificate-info');
    const certificateInfoText = document.getElementById('certificate-info-text');
    const appleProfileFile = document.getElementById('apple-profile-file');
    const appleProfileUploadLabel = document.getElementById('apple-profile-upload-label');
    const appleProfileDetails = document.getElementById('apple-profile-details');
    const teamIdGroup = document.getElementById('team-id-group');

    // Check Apple signing availability on load
    checkAppleSigningAvailability();

    async function checkAppleSigningAvailability() {
        try {
            const response = await fetch('/api/apple/check-platform');
            const result = await response.json();
            isAppleSigningAvailable = result.available;

            if (!isAppleSigningAvailable && appleSigningNotice) {
                appleSigningNotice.style.display = 'flex';
            }
        } catch (error) {
            console.error('Failed to check Apple signing availability:', error);
            isAppleSigningAvailable = false;
        }
    }

    // Handle platform selection for keystore/Apple signing visibility
    platformSelect.addEventListener('change', function() {
        const selectedPlatform = this.value;
        const isAndroid = selectedPlatform === 'android' || selectedPlatform === 'android_aab';
        const isApple = selectedPlatform === 'ios' || selectedPlatform === 'macos';

        keystoreSection.style.display = isAndroid ? 'block' : 'none';
        appleSigningSection.style.display = isApple ? 'block' : 'none';
    });

    // Handle icon file selection
    iconFile.addEventListener('change', function() {
        if (this.files && this.files.length > 0) {
            const file = this.files[0];
            const reader = new FileReader();

            reader.onload = function(e) {
                iconPreview.innerHTML = `<img src="${e.target.result}" alt="App Icon">`;
                iconPreview.classList.add('has-icon');
            };

            reader.readAsDataURL(file);

            iconUploadLabel.innerHTML = `
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                <span>Change Icon</span>
            `;
        }
    });

    // Handle splash screen toggle
    if (enableSplashScreen && splashScreenDetails) {
        enableSplashScreen.addEventListener('change', function() {
            splashScreenDetails.style.display = this.checked ? 'block' : 'none';
        });
    }

    // Handle error page toggle
    if (enableErrorPage && errorPageDetails) {
        enableErrorPage.addEventListener('change', function() {
            errorPageDetails.style.display = this.checked ? 'block' : 'none';
        });
    }

    // Handle splash image file selection
    if (splashImageFile && splashImagePreview) {
        splashImageFile.addEventListener('change', function() {
            if (this.files && this.files.length > 0) {
                const file = this.files[0];
                const reader = new FileReader();
                reader.onload = function(e) {
                    splashImagePreview.innerHTML = `<img src="${e.target.result}" alt="Splash Image" style="width: 100%; height: 100%; object-fit: contain;">`;
                    splashImagePreview.classList.add('has-icon');
                };
                reader.readAsDataURL(file);
                if (splashImageUploadLabel) {
                    splashImageUploadLabel.innerHTML = `
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        <span>Change Splash Image</span>
                    `;
                }
            }
        });
    }

    // Handle error image file selection
    if (errorImageFile && errorImagePreview) {
        errorImageFile.addEventListener('change', function() {
            if (this.files && this.files.length > 0) {
                const file = this.files[0];
                const reader = new FileReader();
                reader.onload = function(e) {
                    errorImagePreview.innerHTML = `<img src="${e.target.result}" alt="Error Image" style="width: 100%; height: 100%; object-fit: contain;">`;
                    errorImagePreview.classList.add('has-icon');
                };
                reader.readAsDataURL(file);
                if (errorImageUploadLabel) {
                    errorImageUploadLabel.innerHTML = `
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        <span>Change Error Image</span>
                    `;
                }
            }
        });
    }

    // Color picker synchronizers
    function bindColorSync(colorPickerId, hexInputId) {
        const picker = document.getElementById(colorPickerId);
        const hex = document.getElementById(hexInputId);
        if (picker && hex) {
            picker.addEventListener('input', function() {
                hex.value = this.value.toUpperCase();
            });
            hex.addEventListener('input', function() {
                let val = this.value.trim();
                if (!val.startsWith('#')) val = '#' + val;
                if (/^#[0-9A-Fa-f]{6}$/.test(val)) {
                    picker.value = val;
                }
            });
        }
    }
    bindColorSync('splash-bg-color', 'splash-bg-color-hex');
    bindColorSync('splash-text-color', 'splash-text-color-hex');
    bindColorSync('error-bg-color', 'error-bg-color-hex');
    bindColorSync('error-text-color', 'error-text-color-hex');

    // Handle keystore file selection
    keystoreFile.addEventListener('change', function() {
        if (this.files && this.files.length > 0) {
            const fileName = this.files[0].name;
            keystoreUploadLabel.innerHTML = `
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                <span>${fileName}</span>
                <small class="hint">Click to change file</small>
            `;
            keystoreUploadLabel.style.borderColor = 'var(--success)';
            keystoreUploadLabel.style.background = 'var(--success-bg)';
            keystoreDetails.style.display = 'block';
        } else {
            resetKeystoreUpload();
        }
    });

    function resetKeystoreUpload() {
        keystoreUploadLabel.innerHTML = `
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12"/>
            </svg>
            <span>Click to upload or drag and drop</span>
            <small class="hint">.jks or .keystore file</small>
        `;
        keystoreUploadLabel.style.borderColor = '';
        keystoreUploadLabel.style.background = '';
        keystoreDetails.style.display = 'none';
    }

    // Handle URL input for preview
    let debounceTimer;
    webUrlInput.addEventListener('input', function() {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            updatePreview(this.value);
        }, 400);
    });

    function normalizeUrl(string) {
        if (!string) return '';
        string = string.trim();
        if (!/^https?:\/\//i.test(string)) {
            return 'https://' + string;
        }
        return string;
    }

    function isValidUrl(string) {
        if (!string) return false;
        const normalized = normalizeUrl(string);
        try {
            const url = new URL(normalized);
            return (url.protocol === 'http:' || url.protocol === 'https:') && (url.hostname.includes('.') || url.hostname === 'localhost');
        } catch (_) {
            return false;
        }
    }

    function updatePreview(url) {
        if (url && isValidUrl(url)) {
            const normalized = normalizeUrl(url);
            placeholderContent.style.display = 'none';
            previewIframe.style.display = 'block';
            if (previewLoading) previewLoading.style.display = 'flex';

            const activeDeviceBtn = document.querySelector('.device-btn.active');
            const device = activeDeviceBtn ? (activeDeviceBtn.dataset.device || 'mobile') : 'mobile';

            previewIframe.src = '/api/preview-proxy?url=' + encodeURIComponent(normalized) + '&device=' + encodeURIComponent(device);
        } else {
            placeholderContent.style.display = 'flex';
            previewIframe.style.display = 'none';
            if (previewLoading) previewLoading.style.display = 'none';
            previewIframe.src = '';
        }
    }

    // Handle device selection
    deviceButtons.forEach(button => {
        button.addEventListener('click', function() {
            deviceButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');

            const device = this.dataset.device;
            deviceFrame.className = 'device-frame ' + device;

            // Re-render preview with matching device user agent if URL is present
            if (webUrlInput && webUrlInput.value && isValidUrl(webUrlInput.value)) {
                updatePreview(webUrlInput.value);
            }
        });
    });

    // Handle mobile/tablet view switcher (Configure App vs Live Preview)
    const viewSwitchConfig = document.getElementById('view-switch-config');
    const viewSwitchPreview = document.getElementById('view-switch-preview');
    const builderMainContainer = document.getElementById('builder-main-container');

    if (viewSwitchConfig && viewSwitchPreview && builderMainContainer) {
        viewSwitchConfig.addEventListener('click', function() {
            viewSwitchConfig.classList.add('active');
            viewSwitchPreview.classList.remove('active');
            builderMainContainer.classList.remove('show-preview');
            builderMainContainer.classList.add('show-config');
        });

        viewSwitchPreview.addEventListener('click', function() {
            viewSwitchPreview.classList.add('active');
            viewSwitchConfig.classList.remove('active');
            builderMainContainer.classList.remove('show-config');
            builderMainContainer.classList.add('show-preview');
        });
    }

    // Handle form submission
    form.addEventListener('submit', async function(e) {
        e.preventDefault();

        const selectedPlatform = platformSelect.value;

        // Validate platform selection
        if (!selectedPlatform) {
            showToast('Please select a target platform', 'error');
            return;
        }

        // Collect form data
        const formData = {
            app_name: document.getElementById('app-name').value,
            app_description: document.getElementById('app-description').value,
            app_version: document.getElementById('app-version').value,
            build_number: document.getElementById('build-number').value,
            package_name: document.getElementById('package-name').value,
            web_url: normalizeUrl(document.getElementById('web-url').value),
            platforms: [selectedPlatform],
            // WebView feature options from hidden checkboxes
            allow_zoom: document.getElementById('allow-zoom').checked,
            enable_javascript: document.getElementById('enable-javascript').checked,
            enable_dom_storage: document.getElementById('enable-dom-storage').checked,
            enable_geolocation: document.getElementById('enable-geolocation').checked,
            enable_pull_refresh: document.getElementById('enable-pull-refresh').checked,
            show_navigation: document.getElementById('show-navigation').checked,
            enable_file_access: document.getElementById('enable-file-access').checked,
            enable_cache: document.getElementById('enable-cache').checked,
            enable_media_autoplay: document.getElementById('enable-media-autoplay').checked,
            enable_camera: document.getElementById('enable-camera').checked,
            enable_microphone: document.getElementById('enable-microphone').checked,
            enable_ssl_pinning: document.getElementById('enable-ssl-pinning').checked,
            ssl_pins: document.getElementById('ssl-pins').value,
            enable_biometric_auth: document.getElementById('enable-biometrics').checked,
            enable_app_lock: document.getElementById('enable-app-lock').checked,
            app_lock_pin: document.getElementById('app-lock-pin').value,
            enable_secure_storage: document.getElementById('enable-secure-storage').checked
        };

        // Check if Android platform and handle keystore
        const isAndroid = selectedPlatform === 'android' || selectedPlatform === 'android_aab';

        // Upload app icon if provided
        if (iconFile.files && iconFile.files.length > 0) {
            try {
                const iconFormData = new FormData();
                iconFormData.append('icon', iconFile.files[0]);

                const iconResponse = await fetch('/api/upload/icon', {
                    method: 'POST',
                    body: iconFormData
                });

                if (iconResponse.ok) {
                    const iconResult = await iconResponse.json();
                    formData.icon_path = iconResult.path;
                    currentIconPath = iconResult.path;
                }
            } catch (error) {
                console.error('Icon upload error:', error);
            }
        }

        // Upload custom splash image if provided
        if (splashImageFile && splashImageFile.files && splashImageFile.files.length > 0) {
            try {
                const splashFormData = new FormData();
                splashFormData.append('splash_image', splashImageFile.files[0]);

                const splashResponse = await fetch('/api/upload/splash-image', {
                    method: 'POST',
                    body: splashFormData
                });

                if (splashResponse.ok) {
                    const splashResult = await splashResponse.json();
                    formData.splash_image_path = splashResult.path;
                    currentSplashImagePath = splashResult.path;
                }
            } catch (error) {
                console.error('Splash image upload error:', error);
            }
        } else if (currentSplashImagePath) {
            formData.splash_image_path = currentSplashImagePath;
        }

        // Upload custom error image if provided
        if (errorImageFile && errorImageFile.files && errorImageFile.files.length > 0) {
            try {
                const errorFormData = new FormData();
                errorFormData.append('error_image', errorImageFile.files[0]);

                const errorResponse = await fetch('/api/upload/error-image', {
                    method: 'POST',
                    body: errorFormData
                });

                if (errorResponse.ok) {
                    const errorResult = await errorResponse.json();
                    formData.error_image_path = errorResult.path;
                    currentErrorImagePath = errorResult.path;
                }
            } catch (error) {
                console.error('Error image upload error:', error);
            }
        } else if (currentErrorImagePath) {
            formData.error_image_path = currentErrorImagePath;
        }

        // Add Splash Screen & Error Page configuration
        formData.enable_splash_screen = document.getElementById('enable-splash-screen')?.checked ?? false;
        formData.splash_title = document.getElementById('splash-title')?.value || '';
        formData.splash_subtitle = document.getElementById('splash-subtitle')?.value || '';
        formData.splash_bg_color = document.getElementById('splash-bg-color')?.value || '#FFFFFF';
        formData.splash_text_color = document.getElementById('splash-text-color')?.value || '#1E293B';
        formData.splash_duration = parseInt(document.getElementById('splash-duration')?.value || '2', 10);

        formData.enable_error_page = document.getElementById('enable-error-page')?.checked ?? false;
        formData.error_title = document.getElementById('error-title')?.value || 'No Internet Connection';
        formData.error_message = document.getElementById('error-message')?.value || 'Please check your connection and try again';
        formData.error_button_text = document.getElementById('error-button-text')?.value || 'Retry';
        formData.error_bg_color = document.getElementById('error-bg-color')?.value || '#FFFFFF';
        formData.error_text_color = document.getElementById('error-text-color')?.value || '#334155';

        if (isAndroid && keystoreFile.files && keystoreFile.files.length > 0) {
            // Upload keystore first
            try {
                const keystoreFormData = new FormData();
                keystoreFormData.append('keystore', keystoreFile.files[0]);

                const uploadResponse = await fetch('/api/upload/keystore', {
                    method: 'POST',
                    body: keystoreFormData
                });

                if (uploadResponse.ok) {
                    const uploadResult = await uploadResponse.json();
                    formData.keystore_path = uploadResult.path;
                    currentKeystorePath = uploadResult.path;
                    formData.keystore_password = document.getElementById('keystore-password').value;
                    formData.key_alias = document.getElementById('key-alias').value;
                    formData.key_password = document.getElementById('key-password').value;
                }
            } catch (error) {
                console.error('Keystore upload error:', error);
            }
        }

        // Check if Apple platform and add signing credentials
        const isApple = selectedPlatform === 'ios' || selectedPlatform === 'macos';
        if (isApple) {
            // Add Apple signing credentials if available
            if (currentAppleCertificatePath) {
                formData.apple_certificate_path = currentAppleCertificatePath;
                formData.apple_certificate_password = document.getElementById('apple-certificate-password').value;
            }
            if (currentAppleProfilePath) {
                formData.apple_provisioning_profile_path = currentAppleProfilePath;
            }
            const teamId = document.getElementById('team-id').value;
            if (teamId) {
                formData.team_id = teamId;
            } else if (currentAppleProfileInfo && currentAppleProfileInfo.team_id) {
                formData.team_id = currentAppleProfileInfo.team_id;
            }
        }

        // Add Store Publishing configuration
        const enableGooglePlay = document.getElementById('enable-google-play-publish')?.checked || false;
        if (enableGooglePlay) {
            formData.enable_google_play_publish = true;
            formData.play_service_account_path = currentPlayKeyPath;
            formData.play_track = document.getElementById('play-track')?.value || 'internal';
            formData.play_status = document.getElementById('play-status')?.value || 'draft';
        }

        const enableAppStore = document.getElementById('enable-app-store-publish')?.checked || false;
        if (enableAppStore) {
            formData.enable_app_store_publish = true;
            formData.app_store_key_path = currentAppStoreKeyPath;
            formData.app_store_key_id = (document.getElementById('app-store-key-id')?.value || '').trim();
            formData.app_store_issuer_id = (document.getElementById('app-store-issuer-id')?.value || '').trim();
        }

        // Disable button and show progress
        buildButton.disabled = true;
        buildProgress.style.display = 'block';
        buildComplete.style.display = 'none';

        // Focus config view on mobile so user sees the progress panel
        if (viewSwitchConfig && builderMainContainer) {
            viewSwitchConfig.classList.add('active');
            if (viewSwitchPreview) viewSwitchPreview.classList.remove('active');
            builderMainContainer.classList.remove('show-preview');
            builderMainContainer.classList.add('show-config');
        }

        // Include project_id if available
        const effectivePid = (typeof currentProjectId !== 'undefined' && currentProjectId) 
            ? currentProjectId 
            : (window.currentProjectId || null);
        if (effectivePid) {
            formData.project_id = effectivePid;
        }

        // Show center progress bar and hide dropdown
        platformDropdownWrapper.style.display = 'none';
        centerProgress.style.display = 'flex';

        try {
            // Start build
            const response = await fetch('/api/build', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Build failed to start');
            }

            const result = await response.json();
            activeBuildId = result.build_id;

            if (result.project_id) {
                if (typeof currentProjectId !== 'undefined') {
                    currentProjectId = result.project_id;
                }
                window.currentProjectId = result.project_id;
                try {
                    const curUrl = new URL(window.location.href);
                    if (curUrl.searchParams.get('project') !== result.project_id) {
                        curUrl.searchParams.set('project', result.project_id);
                        window.history.pushState({}, '', curUrl.toString());
                    }
                } catch (urlErr) {}
            }

            // Persist to localStorage for cross-page navigation
            localStorage.setItem('iewebnative_active_build', JSON.stringify({
                buildId: activeBuildId,
                appName: formData.app_name || 'App',
                startTime: Date.now()
            }));

            // Poll for status
            pollBuildStatus(activeBuildId);

        } catch (error) {
            console.error('Build error:', error);
            showToast('Error starting build: ' + error.message, 'error');
            resetBuildUI();
        }
    });

    function resetBuildUI() {
        if (window._buildCompleteDismissTimer) {
            clearInterval(window._buildCompleteDismissTimer);
            window._buildCompleteDismissTimer = null;
        }
        if (window._pollStatusTimer) {
            clearTimeout(window._pollStatusTimer);
            window._pollStatusTimer = null;
        }
        buildButton.disabled = false;
        buildProgress.style.display = 'none';
        centerProgress.style.display = 'none';
        platformDropdownWrapper.style.display = 'flex';
        centerProgressFill.style.width = '0%';
        progressFill.style.width = '0%';
        activeBuildId = null;
    }

    function closeBuildCompleteModal() {
        if (window._buildCompleteDismissTimer) {
            clearInterval(window._buildCompleteDismissTimer);
            window._buildCompleteDismissTimer = null;
        }
        if (window._pollStatusTimer) {
            clearTimeout(window._pollStatusTimer);
            window._pollStatusTimer = null;
        }
        fetch('/api/build/active/dismiss', { method: 'POST' }).catch(() => {});
        localStorage.removeItem('iewebnative_active_build');

        if (buildComplete) {
            buildComplete.style.opacity = '0';
            buildComplete.style.transform = 'translateY(-6px)';
            setTimeout(() => {
                buildComplete.style.display = 'none';
                buildComplete.style.opacity = '1';
                buildComplete.style.transform = 'none';
                resetBuildUI();
            }, 250);
        } else {
            resetBuildUI();
        }
    }

    function renderBuildComplete(buildId, status) {
        // Show completion
        buildProgress.style.display = 'none';
        buildComplete.style.display = 'block';
        buildComplete.style.opacity = '1';
        buildComplete.style.transform = 'none';
        buildButton.disabled = false;

        // Hide center progress and show dropdown
        centerProgress.style.display = 'none';
        platformDropdownWrapper.style.display = 'flex';
        centerProgressFill.style.width = '0%';

        localStorage.removeItem('iewebnative_active_build');
        showToast('Build completed! Saved to your project dashboard.', 'success');

        // Start 5-second auto-close countdown
        let buildCompleteCountdown = 5;
        const countdownSpan = document.getElementById('build-complete-seconds');
        const timerNotice = document.getElementById('build-complete-timer-notice');
        if (countdownSpan) countdownSpan.textContent = '5';
        if (timerNotice) {
            timerNotice.innerHTML = 'Auto-closing in <span id="build-complete-seconds" style="font-weight: 700; color: #10b981;">5</span>s (saved to Dashboard)';
        }

        if (window._buildCompleteDismissTimer) {
            clearInterval(window._buildCompleteDismissTimer);
            window._buildCompleteDismissTimer = null;
        }

        window._buildCompleteDismissTimer = setInterval(() => {
            buildCompleteCountdown--;
            const currSpan = document.getElementById('build-complete-seconds');
            if (currSpan) currSpan.textContent = buildCompleteCountdown;
            if (buildCompleteCountdown <= 0) {
                clearInterval(window._buildCompleteDismissTimer);
                window._buildCompleteDismissTimer = null;
                closeBuildCompleteModal();
            }
        }, 1000);

        if (!window.currentProjectBuilds) window.currentProjectBuilds = {};
        if (status.outputs) {
            for (const [platform, path] of Object.entries(status.outputs)) {
                if (!path.startsWith('Error:')) {
                    const fname = path.split('/').pop().split('\\').pop();
                    window.currentProjectBuilds[platform] = {
                        buildId: buildId,
                        platform: platform,
                        fileName: fname,
                        downloadUrl: `/api/build/${buildId}/download/${platform}`,
                        builtAt: new Date().toISOString(),
                        status: 'completed'
                    };
                }
            }
        }
        const activePid = window.currentProjectId || (typeof currentProjectId !== 'undefined' ? currentProjectId : null);
        if (activePid) {
            fetch(`/api/projects/${activePid}`).then(r => r.json()).then(data => {
                if (data && data.project && data.project.builds) {
                    window.currentProjectBuilds = Object.assign({}, window.currentProjectBuilds, data.project.builds);
                }
            }).catch(e => console.debug('Sync project builds error:', e));
        }

        const getPlatformDisplayName = (plat) => {
            const names = {
                'android': 'Android APK',
                'android_aab': 'Android (.aab)',
                'ios': 'iOS (.ipa)',
                'ios_xcode': 'Xcode Project (TestFlight)',
                'windows': 'Windows (.zip)',
                'macos': 'macOS (.dmg)',
                'linux': 'Linux (.tar.gz)'
            };
            return names[plat] || plat.toUpperCase();
        };

        // Generate download links
        downloadLinks.innerHTML = '';
        if (status.outputs) {
            for (const [platform, path] of Object.entries(status.outputs)) {
                if (path.startsWith('Error:')) {
                    const errorBtn = document.createElement('span');
                    errorBtn.className = 'download-btn error';
                    errorBtn.innerHTML = `
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="15" y1="9" x2="9" y2="15"/>
                            <line x1="9" y1="9" x2="15" y2="15"/>
                        </svg>
                        ${getPlatformDisplayName(platform)} failed
                    `;
                    errorBtn.title = path;
                    downloadLinks.appendChild(errorBtn);
                } else {
                    const link = document.createElement('a');
                    link.href = `/api/build/${buildId}/download/${platform}`;
                    link.className = 'download-btn';
                    link.innerHTML = `
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                            <polyline points="7 10 12 15 17 10"/>
                            <line x1="12" y1="15" x2="12" y2="3"/>
                        </svg>
                        Download ${getPlatformDisplayName(platform)}
                    `;
                    downloadLinks.appendChild(link);
                }
            }

            // Add keystore download link if generated
            if (status.keystore_generated) {
                const keystoreLink = document.createElement('a');
                keystoreLink.href = `/api/build/${buildId}/download/keystore`;
                keystoreLink.className = 'download-btn';
                keystoreLink.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0110 0v4"/>
                    </svg>
                    Download Keystore
                `;
                keystoreLink.title = 'Save this keystore for future app updates';
                downloadLinks.appendChild(keystoreLink);
            }

            // Add export source code button
            const exportLink = document.createElement('a');
            exportLink.href = `/api/build/${buildId}/export`;
            exportLink.className = 'download-btn secondary';
            exportLink.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/>
                    <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
                    <line x1="12" y1="22.08" x2="12" y2="12"/>
                </svg>
                Export Flutter Source (.zip)
            `;
            exportLink.title = 'Download complete source code with CI/CD build workflows';
            downloadLinks.appendChild(exportLink);

            // Add Google Play Console link if published
            if (status.google_play_published || document.getElementById('enable-google-play-publish')?.checked) {
                const playConsoleBtn = document.createElement('a');
                playConsoleBtn.href = 'https://play.google.com/console';
                playConsoleBtn.target = '_blank';
                playConsoleBtn.rel = 'noopener noreferrer';
                playConsoleBtn.className = 'download-btn';
                playConsoleBtn.style.background = 'linear-gradient(135deg, #01875f, #005c41)';
                playConsoleBtn.style.color = '#ffffff';
                playConsoleBtn.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M3.609 1.814L13.792 12 3.61 22.186a1.996 1.996 0 01-.61-.926V2.74c0-.348.094-.67.252-.951l.357.025zM14.852 13.06l2.808 2.808-11.888 6.793 9.08-9.601zm0-2.12L5.772 1.34 17.66 8.132l-2.808 2.808zm1.06 1.06l3.548 2.028a1.5 1.5 0 000-2.608l-3.548-2.028 1.572 1.572-1.572 1.036z"/>
                    </svg>
                    Open Google Play Console
                `;
                downloadLinks.appendChild(playConsoleBtn);
            }

            // Add App Store Connect link if published
            if (status.app_store_published || document.getElementById('enable-app-store-publish')?.checked) {
                const ascBtn = document.createElement('a');
                ascBtn.href = 'https://appstoreconnect.apple.com/apps';
                ascBtn.target = '_blank';
                ascBtn.rel = 'noopener noreferrer';
                ascBtn.className = 'download-btn';
                ascBtn.style.background = 'linear-gradient(135deg, #1d1d1f, #000000)';
                ascBtn.style.color = '#ffffff';
                ascBtn.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 6.37c.61-.75 1.04-1.8 0.92-2.85-.92.04-2.02.62-2.66 1.37-.56.65-.96 1.69-.83 2.7.99.08 2.03-.54 2.57-1.22z"/>
                    </svg>
                    Open App Store Connect
                `;
                downloadLinks.appendChild(ascBtn);
            }
        }
    }

    async function pollBuildStatus(buildId) {
        if (!buildId) return;
        try {
            const response = await fetch(`/api/build/${buildId}/status`);

            if (!response.ok) {
                throw new Error('Failed to get build status');
            }

            const status = await response.json();

            if (status.status === 'cancelled') {
                if (window._pollStatusTimer) {
                    clearTimeout(window._pollStatusTimer);
                    window._pollStatusTimer = null;
                }
                showToast('Build was cancelled.', 'info');
                localStorage.removeItem('iewebnative_active_build');
                resetBuildUI();
                return;
            }

            if (status.status === 'completed') {
                if (window._pollStatusTimer) {
                    clearTimeout(window._pollStatusTimer);
                    window._pollStatusTimer = null;
                }
                renderBuildComplete(buildId, status);
                showToast('Build completed successfully!', 'success');
                return;
            } else if (status.status === 'error' || status.status === 'failed') {
                if (window._pollStatusTimer) {
                    clearTimeout(window._pollStatusTimer);
                    window._pollStatusTimer = null;
                }
                showToast('Build failed: ' + status.message, 'error');
                localStorage.removeItem('iewebnative_active_build');
                resetBuildUI();
                return;
            }

            // Update progress UI (both sidebar and center)
            progressFill.style.width = status.progress + '%';
            progressPercent.textContent = status.progress + '%';
            progressMessage.textContent = status.message;

            // Update center progress bar
            centerProgressFill.style.width = status.progress + '%';
            centerProgressText.textContent = status.message;

            // Continue polling in background
            if (window._pollStatusTimer) clearTimeout(window._pollStatusTimer);
            window._pollStatusTimer = setTimeout(() => pollBuildStatus(buildId), 1500);
        } catch (error) {
            console.error('Status poll error:', error);
            // Don't immediately wipe out UI on transient network glitches
            if (window._pollStatusTimer) clearTimeout(window._pollStatusTimer);
            window._pollStatusTimer = setTimeout(() => pollBuildStatus(buildId), 3000);
        }
    }

    // Cancel active build button listener
    const cancelBuildBtn = document.getElementById('cancel-build-btn');
    if (cancelBuildBtn) {
        cancelBuildBtn.addEventListener('click', async function() {
            if (!activeBuildId) return;
            if (!confirm('Are you sure you want to cancel the build?')) return;

            cancelBuildBtn.disabled = true;
            const originalHtml = cancelBuildBtn.innerHTML;
            cancelBuildBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg> Cancelling...';

            if (window._pollStatusTimer) {
                clearTimeout(window._pollStatusTimer);
                window._pollStatusTimer = null;
            }

            const targetBid = activeBuildId;
            activeBuildId = null;
            localStorage.removeItem('iewebnative_active_build');

            try {
                const resp = await fetch(`/api/build/${targetBid}/cancel`, { method: 'POST' });
                showToast('Build cancelled.', 'info');
            } catch (err) {
                showToast('Error cancelling build: ' + err.message, 'error');
            } finally {
                cancelBuildBtn.disabled = false;
                cancelBuildBtn.innerHTML = originalHtml;
                resetBuildUI();
            }
        });
    }

    // Start another build button listener
    const startNewBuildBtn = document.getElementById('start-new-build-btn');
    if (startNewBuildBtn) {
        startNewBuildBtn.addEventListener('click', function() {
            closeBuildCompleteModal();
        });
    }

    // Close build complete buttons (X button and Close button)
    const closeBuildCompleteX = document.getElementById('close-build-complete-x');
    if (closeBuildCompleteX) {
        closeBuildCompleteX.addEventListener('click', function() {
            closeBuildCompleteModal();
        });
    }

    const closeBuildCompleteBtn = document.getElementById('close-build-complete-btn');
    if (closeBuildCompleteBtn) {
        closeBuildCompleteBtn.addEventListener('click', function() {
            closeBuildCompleteModal();
        });
    }

    // Pause countdown if user hovers over build complete card
    if (buildComplete) {
        buildComplete.addEventListener('mouseenter', function() {
            if (window._buildCompleteDismissTimer) {
                clearInterval(window._buildCompleteDismissTimer);
                window._buildCompleteDismissTimer = null;
                const timerNotice = document.getElementById('build-complete-timer-notice');
                if (timerNotice) {
                    timerNotice.innerHTML = 'Saved to your project in the Dashboard';
                }
            }
        });
    }

    // Auto-resume active build on page load (e.g. returning from Dashboard)
    async function checkAndResumeActiveBuild() {
        let candidateBuildId = null;
        const stored = localStorage.getItem('iewebnative_active_build');
        if (stored) {
            try {
                const parsed = JSON.parse(stored);
                candidateBuildId = parsed.buildId;
            } catch (e) {}
        }

        // Also check backend session/user active build
        if (!candidateBuildId) {
            try {
                const res = await fetch('/api/build/active');
                if (res.ok) {
                    const data = await res.json();
                    if (data && data.has_active_build && data.build_id) {
                        candidateBuildId = data.build_id;
                    }
                }
            } catch (e) {
                console.warn('Active build check notice:', e);
            }
        }

        if (!candidateBuildId) return;

        try {
            const resp = await fetch(`/api/build/${candidateBuildId}/status`);
            if (!resp.ok) {
                localStorage.removeItem('iewebnative_active_build');
                return;
            }
            const status = await resp.json();
            const activeStatuses = ['preparing', 'building', 'running', 'in_progress', 'queued', 'configuring', 'keystore', 'renaming', 'icons', 'dependencies'];

            // ONLY resume if the build is STILL ACTIVELY IN PROGRESS!
            // Never open the modal if the build already completed, was cancelled, or failed!
            if (activeStatuses.includes(status.status)) {
                activeBuildId = candidateBuildId;
                buildButton.disabled = true;
                buildProgress.style.display = 'block';
                buildComplete.style.display = 'none';

                if (viewSwitchConfig && builderMainContainer) {
                    viewSwitchConfig.classList.add('active');
                    if (viewSwitchPreview) viewSwitchPreview.classList.remove('active');
                    builderMainContainer.classList.remove('show-preview');
                    builderMainContainer.classList.add('show-config');
                }

                if (platformDropdownWrapper) platformDropdownWrapper.style.display = 'none';
                if (centerProgress) centerProgress.style.display = 'flex';

                progressFill.style.width = (status.progress || 10) + '%';
                progressPercent.textContent = (status.progress || 10) + '%';
                progressMessage.textContent = status.message || 'Resuming build in background...';

                if (centerProgressFill) centerProgressFill.style.width = (status.progress || 10) + '%';
                if (centerProgressText) centerProgressText.textContent = status.message || 'Resuming build in background...';

                showToast(`Resumed background build: ${status.app_name || 'App'}`, 'info');
                pollBuildStatus(candidateBuildId);
            } else {
                // Completed, cancelled or failed from earlier: clear active build and dismiss!
                localStorage.removeItem('iewebnative_active_build');
                fetch('/api/build/active/dismiss', { method: 'POST' }).catch(() => {});
            }
        } catch (e) {
            console.warn('Active build check error:', e);
        }
    }

    // Check for running builds upon loading builder
    checkAndResumeActiveBuild();

    function getPlatformDisplayName(platform) {
        const names = {
            'android': 'Android APK',
            'android_aab': 'Android AAB',
            'ios': 'iOS (.ipa)',
            'ios_xcode': 'Xcode Project (TestFlight)',
            'macos': 'macOS',
            'windows': 'Windows',
            'linux': 'Linux'
        };
        return names[platform] || platform;
    }

    // Toast notification function
    function showToast(message, type = 'info') {
        // Remove existing toasts
        const existingToast = document.querySelector('.toast');
        if (existingToast) {
            existingToast.remove();
        }

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icon = type === 'success'
            ? '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
            : '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';

        toast.innerHTML = `${icon}<span>${message}</span>`;
        document.body.appendChild(toast);

        // Remove toast after 4 seconds
        setTimeout(() => {
            toast.style.animation = 'slideIn 0.2s ease reverse';
            setTimeout(() => toast.remove(), 200);
        }, 4000);
    }

    // Auto-generate package name from app name
    const appNameInput = document.getElementById('app-name');
    const packageNameInput = document.getElementById('package-name');

    appNameInput.addEventListener('input', function() {
        if (!packageNameInput.dataset.userModified) {
            const sanitized = this.value.toLowerCase()
                .replace(/[^a-z0-9]/g, '')
                .substring(0, 20);
            packageNameInput.value = sanitized ? `com.example.${sanitized}` : '';
        }
    });

    packageNameInput.addEventListener('input', function() {
        this.dataset.userModified = 'true';
    });

    // Drag and drop for keystore
    const keystoreUpload = document.getElementById('keystore-upload');

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        keystoreUpload.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        keystoreUpload.addEventListener(eventName, () => {
            keystoreUploadLabel.style.borderColor = 'var(--primary)';
            keystoreUploadLabel.style.background = 'var(--primary-glow)';
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        keystoreUpload.addEventListener(eventName, () => {
            if (!keystoreFile.files || keystoreFile.files.length === 0) {
                keystoreUploadLabel.style.borderColor = '';
                keystoreUploadLabel.style.background = '';
            }
        }, false);
    });

    keystoreUpload.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length > 0) {
            keystoreFile.files = files;
            const event = new Event('change');
            keystoreFile.dispatchEvent(event);
        }
    }, false);

    // Drag and drop for icon
    const iconUpload = document.getElementById('icon-upload');

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        iconUpload.addEventListener(eventName, preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        iconUpload.addEventListener(eventName, () => {
            iconUploadLabel.style.borderColor = 'var(--primary)';
            iconUploadLabel.style.background = 'var(--primary-glow)';
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        iconUpload.addEventListener(eventName, () => {
            if (!iconFile.files || iconFile.files.length === 0) {
                iconUploadLabel.style.borderColor = '';
                iconUploadLabel.style.background = '';
            }
        }, false);
    });

    iconUpload.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length > 0 && files[0].type.startsWith('image/')) {
            iconFile.files = files;
            const event = new Event('change');
            iconFile.dispatchEvent(event);
        }
    }, false);

    // ==================== APPLE SIGNING HANDLERS ====================

    // Handle Apple certificate file selection
    if (appleCertificateFile) {
        appleCertificateFile.addEventListener('change', function() {
            if (this.files && this.files.length > 0) {
                const fileName = this.files[0].name;
                appleCertificateUploadLabel.innerHTML = `
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                        <polyline points="14 2 14 8 20 8"/>
                        <line x1="16" y1="13" x2="8" y2="13"/>
                        <line x1="16" y1="17" x2="8" y2="17"/>
                    </svg>
                    <span>${fileName}</span>
                    <small class="hint">Click to change file</small>
                `;
                appleCertificateUploadLabel.style.borderColor = 'var(--primary)';
                appleCertificateUploadLabel.style.background = 'var(--primary-glow)';
                appleCertificateDetails.style.display = 'block';

                // Reset certificate validation state
                certificateInfo.style.display = 'none';
                currentAppleCertificatePath = null;
            } else {
                resetAppleCertificateUpload();
            }
        });
    }

    // Validate certificate when password is entered
    if (appleCertificatePassword) {
        let certValidationTimer;
        appleCertificatePassword.addEventListener('input', function() {
            clearTimeout(certValidationTimer);
            certValidationTimer = setTimeout(() => {
                validateAppleCertificate();
            }, 500);
        });
    }

    async function validateAppleCertificate() {
        if (!appleCertificateFile.files || appleCertificateFile.files.length === 0) {
            return;
        }

        const password = appleCertificatePassword.value;
        if (!password) {
            certificateInfo.style.display = 'none';
            return;
        }

        const formData = new FormData();
        formData.append('certificate', appleCertificateFile.files[0]);
        formData.append('password', password);

        try {
            certificateInfoText.textContent = 'Validating certificate...';
            certificateInfo.style.display = 'flex';
            certificateInfo.className = 'certificate-info validating';

            const response = await fetch('/api/upload/apple-certificate', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (response.ok && result.success) {
                currentAppleCertificatePath = result.path;
                certificateInfoText.textContent = 'Certificate validated successfully';
                certificateInfo.className = 'certificate-info success';
                appleCertificateUploadLabel.style.borderColor = 'var(--success)';
                appleCertificateUploadLabel.style.background = 'var(--success-bg)';
            } else {
                currentAppleCertificatePath = null;
                certificateInfoText.textContent = result.error || 'Certificate validation failed';
                certificateInfo.className = 'certificate-info error';
                appleCertificateUploadLabel.style.borderColor = 'var(--error)';
                appleCertificateUploadLabel.style.background = 'var(--error-bg)';
            }
        } catch (error) {
            console.error('Certificate validation error:', error);
            certificateInfoText.textContent = 'Validation failed - check console';
            certificateInfo.className = 'certificate-info error';
        }
    }

    function resetAppleCertificateUpload() {
        appleCertificateUploadLabel.innerHTML = `
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12"/>
            </svg>
            <span>Click to upload or drag and drop</span>
            <small class="hint">.p12 file exported from Keychain Access</small>
        `;
        appleCertificateUploadLabel.style.borderColor = '';
        appleCertificateUploadLabel.style.background = '';
        appleCertificateDetails.style.display = 'none';
        certificateInfo.style.display = 'none';
        currentAppleCertificatePath = null;
    }

    // Handle Apple provisioning profile selection
    if (appleProfileFile) {
        appleProfileFile.addEventListener('change', async function() {
            if (this.files && this.files.length > 0) {
                const file = this.files[0];
                const fileName = file.name;

                appleProfileUploadLabel.innerHTML = `
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-dashoffset="32" class="spin-circle"/>
                    </svg>
                    <span>Validating profile...</span>
                `;
                appleProfileUploadLabel.style.borderColor = 'var(--primary)';
                appleProfileUploadLabel.style.background = 'var(--primary-glow)';

                // Upload and validate the profile
                const formData = new FormData();
                formData.append('profile', file);

                try {
                    const response = await fetch('/api/upload/provisioning-profile', {
                        method: 'POST',
                        body: formData
                    });

                    const result = await response.json();

                    if (response.ok && result.success) {
                        currentAppleProfilePath = result.path;
                        currentAppleProfileInfo = result.info;

                        appleProfileUploadLabel.innerHTML = `
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                                <polyline points="22 4 12 14.01 9 11.01"/>
                            </svg>
                            <span>${fileName}</span>
                            <small class="hint">Click to change file</small>
                        `;
                        appleProfileUploadLabel.style.borderColor = 'var(--success)';
                        appleProfileUploadLabel.style.background = 'var(--success-bg)';

                        // Display profile info
                        appleProfileDetails.style.display = 'block';
                        document.getElementById('profile-name').textContent = result.info.name || '-';
                        document.getElementById('profile-team-id').textContent = result.info.team_id || '-';
                        document.getElementById('profile-bundle-id').textContent = result.info.app_bundle_id || '-';

                        if (result.info.expiration_date) {
                            const expDate = new Date(result.info.expiration_date);
                            document.getElementById('profile-expiration').textContent = expDate.toLocaleDateString();
                        } else {
                            document.getElementById('profile-expiration').textContent = '-';
                        }

                        // Auto-fill team ID if available
                        if (result.info.team_id) {
                            document.getElementById('team-id').value = result.info.team_id;
                        }

                        showToast('Provisioning profile validated', 'success');
                    } else {
                        resetAppleProfileUpload();
                        showToast(result.error || 'Invalid provisioning profile', 'error');
                    }
                } catch (error) {
                    console.error('Profile validation error:', error);
                    resetAppleProfileUpload();
                    showToast('Failed to validate provisioning profile', 'error');
                }
            } else {
                resetAppleProfileUpload();
            }
        });
    }

    function resetAppleProfileUpload() {
        appleProfileUploadLabel.innerHTML = `
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12"/>
            </svg>
            <span>Click to upload or drag and drop</span>
            <small class="hint">.mobileprovision file from Apple Developer Portal</small>
        `;
        appleProfileUploadLabel.style.borderColor = '';
        appleProfileUploadLabel.style.background = '';
        appleProfileDetails.style.display = 'none';
        currentAppleProfilePath = null;
        currentAppleProfileInfo = null;
    }

    // Drag and drop for Apple certificate
    const appleCertificateUpload = document.getElementById('apple-certificate-upload');
    if (appleCertificateUpload) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            appleCertificateUpload.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            appleCertificateUpload.addEventListener(eventName, () => {
                appleCertificateUploadLabel.style.borderColor = 'var(--primary)';
                appleCertificateUploadLabel.style.background = 'var(--primary-glow)';
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            appleCertificateUpload.addEventListener(eventName, () => {
                if (!appleCertificateFile.files || appleCertificateFile.files.length === 0) {
                    appleCertificateUploadLabel.style.borderColor = '';
                    appleCertificateUploadLabel.style.background = '';
                }
            }, false);
        });

        appleCertificateUpload.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;

            if (files.length > 0) {
                const file = files[0];
                if (file.name.endsWith('.p12') || file.name.endsWith('.pfx')) {
                    appleCertificateFile.files = files;
                    const event = new Event('change');
                    appleCertificateFile.dispatchEvent(event);
                } else {
                    showToast('Please upload a .p12 or .pfx file', 'error');
                }
            }
        }, false);
    }

    // Drag and drop for Apple provisioning profile
    const appleProfileUpload = document.getElementById('apple-profile-upload');
    if (appleProfileUpload) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            appleProfileUpload.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            appleProfileUpload.addEventListener(eventName, () => {
                appleProfileUploadLabel.style.borderColor = 'var(--primary)';
                appleProfileUploadLabel.style.background = 'var(--primary-glow)';
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            appleProfileUpload.addEventListener(eventName, () => {
                if (!appleProfileFile.files || appleProfileFile.files.length === 0) {
                    appleProfileUploadLabel.style.borderColor = '';
                    appleProfileUploadLabel.style.background = '';
                }
            }, false);
        });

        appleProfileUpload.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;

            if (files.length > 0) {
                const file = files[0];
                if (file.name.endsWith('.mobileprovision')) {
                    appleProfileFile.files = files;
                    const event = new Event('change');
                    appleProfileFile.dispatchEvent(event);
                } else {
                    showToast('Please upload a .mobileprovision file', 'error');
                }
            }
        }, false);
    }

    // ==================== STORE PUBLISHING HANDLERS ====================

    const enableGooglePlayCb = document.getElementById('enable-google-play-publish');
    const googlePlayDetails = document.getElementById('google-play-details');
    const playServiceAccountFile = document.getElementById('play-service-account-file');
    const playKeyUploadLabel = document.getElementById('play-key-upload-label');
    const playKeyUpload = document.getElementById('play-key-upload');

    const enableAppStoreCb = document.getElementById('enable-app-store-publish');
    const appStoreDetails = document.getElementById('app-store-details');
    const appStoreKeyFile = document.getElementById('app-store-key-file');
    const appStoreKeyUploadLabel = document.getElementById('app-store-key-upload-label');
    const appStoreKeyUpload = document.getElementById('app-store-key-upload');

    if (enableGooglePlayCb) {
        enableGooglePlayCb.addEventListener('change', function() {
            if (googlePlayDetails) {
                googlePlayDetails.style.display = this.checked ? 'block' : 'none';
            }
        });
    }

    if (enableAppStoreCb) {
        enableAppStoreCb.addEventListener('change', function() {
            if (appStoreDetails) {
                appStoreDetails.style.display = this.checked ? 'block' : 'none';
            }
        });
    }

    if (playServiceAccountFile) {
        playServiceAccountFile.addEventListener('change', async function() {
            if (!this.files || this.files.length === 0) return;
            const file = this.files[0];
            const formData = new FormData();
            formData.append('play_key', file);

            try {
                if (playKeyUploadLabel) {
                    playKeyUploadLabel.innerHTML = `<span>Uploading Google Play Key...</span>`;
                }
                const res = await fetch('/api/upload/play-key', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Upload failed');

                currentPlayKeyPath = data.path;
                if (playKeyUploadLabel) {
                    playKeyUploadLabel.innerHTML = `
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        <span>${file.name}</span>
                        <small class="hint">${data.client_email ? data.client_email : 'Service Account Verified'}</small>
                    `;
                    playKeyUploadLabel.style.borderColor = 'var(--success)';
                    playKeyUploadLabel.style.background = 'var(--success-bg)';
                }
                showToast('Google Play Service Account JSON verified!', 'success');
            } catch (err) {
                console.error('Play key upload error:', err);
                currentPlayKeyPath = null;
                if (playKeyUploadLabel) {
                    playKeyUploadLabel.innerHTML = `
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12"/>
                        </svg>
                        <span>Upload Failed</span>
                        <small class="hint">Click to try again</small>
                    `;
                    playKeyUploadLabel.style.borderColor = 'var(--error)';
                    playKeyUploadLabel.style.background = 'var(--error-bg)';
                }
                showToast(err.message, 'error');
            }
        });
    }

    if (appStoreKeyFile) {
        appStoreKeyFile.addEventListener('change', async function() {
            if (!this.files || this.files.length === 0) return;
            const file = this.files[0];
            const formData = new FormData();
            formData.append('app_store_key', file);

            try {
                if (appStoreKeyUploadLabel) {
                    appStoreKeyUploadLabel.innerHTML = `<span>Uploading App Store API Key...</span>`;
                }
                const res = await fetch('/api/upload/app-store-key', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Upload failed');

                currentAppStoreKeyPath = data.path;

                // Auto-fill Key ID from filename if named AuthKey_XXXXXXXXXX.p8
                const match = file.name.match(/AuthKey_([A-Za-z0-9]{10})\.p8/i);
                if (match && match[1]) {
                    const keyIdInput = document.getElementById('app-store-key-id');
                    if (keyIdInput && !keyIdInput.value) {
                        keyIdInput.value = match[1];
                    }
                }

                if (appStoreKeyUploadLabel) {
                    appStoreKeyUploadLabel.innerHTML = `
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        <span>${file.name}</span>
                        <small class="hint">API Key Loaded</small>
                    `;
                    appStoreKeyUploadLabel.style.borderColor = 'var(--success)';
                    appStoreKeyUploadLabel.style.background = 'var(--success-bg)';
                }
                showToast('App Store Connect API Key (.p8) verified!', 'success');
            } catch (err) {
                console.error('App Store key upload error:', err);
                currentAppStoreKeyPath = null;
                if (appStoreKeyUploadLabel) {
                    appStoreKeyUploadLabel.innerHTML = `
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12"/>
                        </svg>
                        <span>Upload Failed</span>
                        <small class="hint">Click to try again</small>
                    `;
                    appStoreKeyUploadLabel.style.borderColor = 'var(--error)';
                    appStoreKeyUploadLabel.style.background = 'var(--error-bg)';
                }
                showToast(err.message, 'error');
            }
        });
    }

    // Drag and drop for Google Play Key
    if (playKeyUpload) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            playKeyUpload.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            playKeyUpload.addEventListener(eventName, () => {
                if (playKeyUploadLabel) {
                    playKeyUploadLabel.style.borderColor = 'var(--primary)';
                    playKeyUploadLabel.style.background = 'var(--primary-glow)';
                }
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            playKeyUpload.addEventListener(eventName, () => {
                if (!playServiceAccountFile.files || playServiceAccountFile.files.length === 0) {
                    if (playKeyUploadLabel) {
                        playKeyUploadLabel.style.borderColor = '';
                        playKeyUploadLabel.style.background = '';
                    }
                }
            }, false);
        });

        playKeyUpload.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0 && playServiceAccountFile) {
                playServiceAccountFile.files = files;
                playServiceAccountFile.dispatchEvent(new Event('change'));
            }
        }, false);
    }

    // Drag and drop for App Store Key
    if (appStoreKeyUpload) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            appStoreKeyUpload.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            appStoreKeyUpload.addEventListener(eventName, () => {
                if (appStoreKeyUploadLabel) {
                    appStoreKeyUploadLabel.style.borderColor = 'var(--primary)';
                    appStoreKeyUploadLabel.style.background = 'var(--primary-glow)';
                }
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            appStoreKeyUpload.addEventListener(eventName, () => {
                if (!appStoreKeyFile.files || appStoreKeyFile.files.length === 0) {
                    if (appStoreKeyUploadLabel) {
                        appStoreKeyUploadLabel.style.borderColor = '';
                        appStoreKeyUploadLabel.style.background = '';
                    }
                }
            }, false);
        });

        appStoreKeyUpload.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0 && appStoreKeyFile) {
                appStoreKeyFile.files = files;
                appStoreKeyFile.dispatchEvent(new Event('change'));
            }
        }, false);
    }

    // ==================== Project Save/Open ====================

    // Save project button handler
    saveProjectBtn.addEventListener('click', async function() {
        const appName = document.getElementById('app-name').value;
        const appVersion = document.getElementById('app-version').value;
        const buildNumber = document.getElementById('build-number').value;

        // Validate required fields
        if (!appName) {
            showToast('Please enter an app name before saving', 'error');
            return;
        }
        if (!appVersion) {
            showToast('Please enter an app version before saving', 'error');
            return;
        }
        if (!buildNumber) {
            showToast('Please enter a build number before saving', 'error');
            return;
        }

        // Upload icon first if present and not already uploaded
        if (iconFile.files && iconFile.files.length > 0 && !currentIconPath) {
            try {
                const iconFormData = new FormData();
                iconFormData.append('icon', iconFile.files[0]);

                const iconResponse = await fetch('/api/upload/icon', {
                    method: 'POST',
                    body: iconFormData
                });

                if (iconResponse.ok) {
                    const iconResult = await iconResponse.json();
                    currentIconPath = iconResult.path;
                }
            } catch (error) {
                console.error('Icon upload error:', error);
            }
        }

        // Upload keystore if present and not already uploaded
        if (keystoreFile.files && keystoreFile.files.length > 0 && !currentKeystorePath) {
            try {
                const keystoreFormData = new FormData();
                keystoreFormData.append('keystore', keystoreFile.files[0]);

                const keystoreResponse = await fetch('/api/upload/keystore', {
                    method: 'POST',
                    body: keystoreFormData
                });

                if (keystoreResponse.ok) {
                    const keystoreResult = await keystoreResponse.json();
                    currentKeystorePath = keystoreResult.path;
                }
            } catch (error) {
                console.error('Keystore upload error:', error);
            }
        }

        // Upload splash image if present and not already uploaded
        if (splashImageFile && splashImageFile.files && splashImageFile.files.length > 0 && !currentSplashImagePath) {
            try {
                const splashFormData = new FormData();
                splashFormData.append('splash_image', splashImageFile.files[0]);
                const splashResp = await fetch('/api/upload/splash-image', {
                    method: 'POST',
                    body: splashFormData
                });
                if (splashResp.ok) {
                    const splashResult = await splashResp.json();
                    currentSplashImagePath = splashResult.path;
                }
            } catch (error) {
                console.error('Splash upload error:', error);
            }
        }

        // Upload error image if present and not already uploaded
        if (errorImageFile && errorImageFile.files && errorImageFile.files.length > 0 && !currentErrorImagePath) {
            try {
                const errorFormData = new FormData();
                errorFormData.append('error_image', errorImageFile.files[0]);
                const errorResp = await fetch('/api/upload/error-image', {
                    method: 'POST',
                    body: errorFormData
                });
                if (errorResp.ok) {
                    const errorResult = await errorResp.json();
                    currentErrorImagePath = errorResult.path;
                }
            } catch (error) {
                console.error('Error upload error:', error);
            }
        }

        // Collect project data
        const projectData = {
            app_name: appName,
            app_description: document.getElementById('app-description').value,
            app_version: appVersion,
            build_number: buildNumber,
            package_name: document.getElementById('package-name').value,
            web_url: document.getElementById('web-url').value,
            // WebView settings
            allow_zoom: document.getElementById('allow-zoom').checked,
            enable_javascript: document.getElementById('enable-javascript').checked,
            enable_dom_storage: document.getElementById('enable-dom-storage').checked,
            enable_geolocation: document.getElementById('enable-geolocation').checked,
            enable_pull_refresh: document.getElementById('enable-pull-refresh').checked,
            show_navigation: document.getElementById('show-navigation').checked,
            enable_file_access: document.getElementById('enable-file-access').checked,
            enable_cache: document.getElementById('enable-cache').checked,
            enable_media_autoplay: document.getElementById('enable-media-autoplay').checked,
            enable_camera: document.getElementById('enable-camera').checked,
            enable_microphone: document.getElementById('enable-microphone').checked,
            enable_ssl_pinning: document.getElementById('enable-ssl-pinning').checked,
            ssl_pins: document.getElementById('ssl-pins').value,
            enable_biometrics: document.getElementById('enable-biometrics').checked,
            enable_app_lock: document.getElementById('enable-app-lock').checked,
            app_lock_pin: document.getElementById('app-lock-pin').value,
            enable_secure_storage: document.getElementById('enable-secure-storage').checked,
            // Keystore info
            keystore_password: document.getElementById('keystore-password').value,
            key_alias: document.getElementById('key-alias').value,
            key_password: document.getElementById('key-password').value,
            // Apple signing info
            apple_certificate_password: document.getElementById('apple-certificate-password').value,
            team_id: document.getElementById('team-id').value,
            // Store Publishing info
            enable_google_play_publish: document.getElementById('enable-google-play-publish')?.checked || false,
            play_track: document.getElementById('play-track')?.value || 'internal',
            play_status: document.getElementById('play-status')?.value || 'draft',
            enable_app_store_publish: document.getElementById('enable-app-store-publish')?.checked || false,
            app_store_key_id: (document.getElementById('app-store-key-id')?.value || '').trim(),
            app_store_issuer_id: (document.getElementById('app-store-issuer-id')?.value || '').trim(),
            // Splash & Error settings
            enable_splash_screen: document.getElementById('enable-splash-screen')?.checked ?? false,
            splash_title: document.getElementById('splash-title')?.value || '',
            splash_subtitle: document.getElementById('splash-subtitle')?.value || '',
            splash_bg_color: document.getElementById('splash-bg-color')?.value || '#FFFFFF',
            splash_text_color: document.getElementById('splash-text-color')?.value || '#1E293B',
            splash_duration: parseInt(document.getElementById('splash-duration')?.value || '2', 10),
            enable_error_page: document.getElementById('enable-error-page')?.checked ?? false,
            error_title: document.getElementById('error-title')?.value || 'No Internet Connection',
            error_message: document.getElementById('error-message')?.value || 'Please check your connection and try again',
            error_button_text: document.getElementById('error-button-text')?.value || 'Retry',
            error_bg_color: document.getElementById('error-bg-color')?.value || '#FFFFFF',
            error_text_color: document.getElementById('error-text-color')?.value || '#334155',
            // Asset paths
            icon_path: currentIconPath,
            keystore_path: currentKeystorePath,
            apple_certificate_path: currentAppleCertificatePath,
            apple_provisioning_profile_path: currentAppleProfilePath,
            play_service_account_path: currentPlayKeyPath,
            app_store_key_path: currentAppStoreKeyPath,
            splash_image_path: currentSplashImagePath,
            error_image_path: currentErrorImagePath
        };

        try {
            saveProjectBtn.disabled = true;
            saveProjectBtn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin">
                    <circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-dashoffset="32"/>
                </svg>
                <span>Saving...</span>
            `;

            const response = await fetch('/api/project/save', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(projectData)
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to save project');
            }

            // Download the file
            const blob = await response.blob();
            const safeName = appName.replace(/[^a-zA-Z0-9_-]/g, '_');
            const filename = `${safeName}_v${appVersion}_${buildNumber}.iewebnative`;

            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();

            showToast('Project saved successfully!', 'success');
        } catch (error) {
            console.error('Save error:', error);
            showToast('Error saving project: ' + error.message, 'error');
        } finally {
            saveProjectBtn.disabled = false;
            saveProjectBtn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                    <polyline points="7 10 12 15 17 10"/>
                    <line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                <span>Download</span>
            `;
        }
    });

    // Open project button handler
    openProjectBtn.addEventListener('click', function() {
        openProjectFile.click();
    });

    // Handle project file selection
    openProjectFile.addEventListener('change', async function() {
        if (!this.files || this.files.length === 0) return;

        const file = this.files[0];
        if (!file.name.endsWith('.iewebnative') && !file.name.endsWith('.swab')) {
            showToast('Please select a project file (.iewebnative or .swab)', 'error');
            return;
        }

        const formData = new FormData();
        formData.append('project', file);

        try {
            openProjectBtn.disabled = true;
            openProjectBtn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin">
                    <circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-dashoffset="32"/>
                </svg>
                <span>Opening...</span>
            `;

            const response = await fetch('/api/project/open', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Failed to open project');
            }

            // Load project data into form
            const project = result.project;

            document.getElementById('app-name').value = project.app_name || '';
            document.getElementById('app-description').value = project.app_description || '';
            document.getElementById('app-version').value = project.app_version || '1.0.0';
            document.getElementById('build-number').value = project.build_number || '1';
            document.getElementById('package-name').value = project.package_name || '';
            document.getElementById('package-name').dataset.userModified = 'true';
            document.getElementById('web-url').value = project.web_url || '';

            // Update preview
            if (project.web_url) {
                updatePreview(project.web_url);
            }

            // WebView settings
            document.getElementById('allow-zoom').checked = project.allow_zoom === true;
            document.getElementById('enable-javascript').checked = project.enable_javascript === true;
            document.getElementById('enable-dom-storage').checked = project.enable_dom_storage === true;
            document.getElementById('enable-geolocation').checked = project.enable_geolocation === true;
            document.getElementById('enable-pull-refresh').checked = project.enable_pull_refresh === true;
            document.getElementById('show-navigation').checked = project.show_navigation === true;
            document.getElementById('enable-file-access').checked = project.enable_file_access === true;
            document.getElementById('enable-cache').checked = project.enable_cache === true;
            document.getElementById('enable-media-autoplay').checked = project.enable_media_autoplay === true;
            document.getElementById('enable-camera').checked = project.enable_camera === true;
            document.getElementById('enable-microphone').checked = project.enable_microphone === true;
            document.getElementById('enable-ssl-pinning').checked = project.enable_ssl_pinning === true;
            document.getElementById('ssl-pins').value = project.ssl_pins || '';
            document.getElementById('enable-biometrics').checked = project.enable_biometrics === true;
            document.getElementById('enable-app-lock').checked = project.enable_app_lock === true;
            document.getElementById('app-lock-pin').value = project.app_lock_pin || '';
            document.getElementById('enable-secure-storage').checked = project.enable_secure_storage === true;

            // Sync settings dialog checkboxes
            document.getElementById('setting-allow-zoom').checked = project.allow_zoom === true;
            document.getElementById('setting-enable-javascript').checked = project.enable_javascript === true;
            document.getElementById('setting-enable-dom-storage').checked = project.enable_dom_storage === true;
            document.getElementById('setting-enable-geolocation').checked = project.enable_geolocation === true;
            document.getElementById('setting-enable-pull-refresh').checked = project.enable_pull_refresh === true;
            document.getElementById('setting-show-navigation').checked = project.show_navigation === true;
            document.getElementById('setting-enable-file-access').checked = project.enable_file_access === true;
            document.getElementById('setting-enable-cache').checked = project.enable_cache === true;
            document.getElementById('setting-enable-media-autoplay').checked = project.enable_media_autoplay === true;
            document.getElementById('setting-enable-camera').checked = project.enable_camera === true;
            document.getElementById('setting-enable-microphone').checked = project.enable_microphone === true;
            document.getElementById('setting-enable-ssl-pinning').checked = project.enable_ssl_pinning === true;
            document.getElementById('setting-ssl-pins').value = project.ssl_pins || '';
            document.getElementById('setting-enable-biometrics').checked = project.enable_biometrics === true;
            document.getElementById('setting-enable-app-lock').checked = project.enable_app_lock === true;
            document.getElementById('setting-app-lock-pin').value = project.app_lock_pin || '';
            document.getElementById('setting-enable-secure-storage').checked = project.enable_secure_storage === true;

            const openedSslGrp = document.getElementById('ssl-pinning-group');
            if (openedSslGrp) openedSslGrp.style.display = project.enable_ssl_pinning ? 'block' : 'none';
            const openedLockGrp = document.getElementById('app-lock-group');
            if (openedLockGrp) openedLockGrp.style.display = project.enable_app_lock ? 'block' : 'none';

            // Keystore info
            if (project.keystore_password) {
                document.getElementById('keystore-password').value = project.keystore_password;
            }
            if (project.key_alias) {
                document.getElementById('key-alias').value = project.key_alias;
            }
            if (project.key_password) {
                document.getElementById('key-password').value = project.key_password;
            }

            // Handle icon
            if (project.icon_path) {
                currentIconPath = project.icon_path;
                // Show icon preview by loading from uploads
                iconPreview.innerHTML = `<img src="/uploads/${project.icon_path.split('/').pop()}" alt="App Icon" onerror="this.parentElement.innerHTML='<svg width=\\'48\\' height=\\'48\\' viewBox=\\'0 0 24 24\\' fill=\\'none\\' stroke=\\'currentColor\\' stroke-width=\\'1.5\\'><rect x=\\'3\\' y=\\'3\\' width=\\'18\\' height=\\'18\\' rx=\\'4\\' ry=\\'4\\'/><circle cx=\\'8.5\\' cy=\\'8.5\\' r=\\'1.5\\'/><polyline points=\\'21 15 16 10 5 21\\'/></svg>'">`;
                iconPreview.classList.add('has-icon');
                iconUploadLabel.innerHTML = `
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                        <polyline points="22 4 12 14.01 9 11.01"/>
                    </svg>
                    <span>Change Icon</span>
                `;
            }

            // Handle keystore
            if (project.keystore_path) {
                currentKeystorePath = project.keystore_path;
                keystoreUploadLabel.innerHTML = `
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                        <polyline points="22 4 12 14.01 9 11.01"/>
                    </svg>
                    <span>keystore.jks (loaded)</span>
                    <small class="hint">Click to change file</small>
                `;
                keystoreUploadLabel.style.borderColor = 'var(--success)';
                keystoreUploadLabel.style.background = 'var(--success-bg)';
                keystoreDetails.style.display = 'block';

                // Show keystore section if we have keystore data
                keystoreSection.style.display = 'block';
            }

            // Handle Apple certificate
            if (project.apple_certificate_path) {
                currentAppleCertificatePath = project.apple_certificate_path;
                appleCertificateUploadLabel.innerHTML = `
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                        <polyline points="22 4 12 14.01 9 11.01"/>
                    </svg>
                    <span>certificate.p12 (loaded)</span>
                    <small class="hint">Click to change file</small>
                `;
                appleCertificateUploadLabel.style.borderColor = 'var(--success)';
                appleCertificateUploadLabel.style.background = 'var(--success-bg)';
                appleCertificateDetails.style.display = 'block';

                if (project.apple_certificate_password) {
                    document.getElementById('apple-certificate-password').value = project.apple_certificate_password;
                }

                // Show Apple signing section
                appleSigningSection.style.display = 'block';
            }

            // Handle Apple provisioning profile
            if (project.apple_provisioning_profile_path) {
                currentAppleProfilePath = project.apple_provisioning_profile_path;
                currentAppleProfileInfo = project.apple_profile_info || null;

                appleProfileUploadLabel.innerHTML = `
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                        <polyline points="22 4 12 14.01 9 11.01"/>
                    </svg>
                    <span>profile.mobileprovision (loaded)</span>
                    <small class="hint">Click to change file</small>
                `;
                appleProfileUploadLabel.style.borderColor = 'var(--success)';
                appleProfileUploadLabel.style.background = 'var(--success-bg)';

                // Display profile info if available
                if (project.apple_profile_info) {
                    appleProfileDetails.style.display = 'block';
                    document.getElementById('profile-name').textContent = project.apple_profile_info.name || '-';
                    document.getElementById('profile-team-id').textContent = project.apple_profile_info.team_id || '-';
                    document.getElementById('profile-bundle-id').textContent = project.apple_profile_info.app_bundle_id || '-';

                    if (project.apple_profile_info.expiration_date) {
                        const expDate = new Date(project.apple_profile_info.expiration_date);
                        document.getElementById('profile-expiration').textContent = expDate.toLocaleDateString();
                    }
                }

                // Show Apple signing section
                appleSigningSection.style.display = 'block';
            }

            // Handle Team ID
            if (project.team_id) {
                document.getElementById('team-id').value = project.team_id;
            }

            // Handle Store Publishing configuration
            if (project.enable_google_play_publish) {
                const playCb = document.getElementById('enable-google-play-publish');
                if (playCb) playCb.checked = true;
                const playDetails = document.getElementById('google-play-details');
                if (playDetails) playDetails.style.display = 'block';
            }
            if (project.play_track) {
                const playTrackEl = document.getElementById('play-track');
                if (playTrackEl) playTrackEl.value = project.play_track;
            }
            if (project.play_status) {
                const playStatusEl = document.getElementById('play-status');
                if (playStatusEl) playStatusEl.value = project.play_status;
            }
            if (project.play_service_account_path) {
                currentPlayKeyPath = project.play_service_account_path;
                if (playKeyUploadLabel) {
                    playKeyUploadLabel.innerHTML = `
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        <span>Google Play Key Loaded</span>
                        <small class="hint">Click to change file</small>
                    `;
                    playKeyUploadLabel.style.borderColor = 'var(--success)';
                    playKeyUploadLabel.style.background = 'var(--success-bg)';
                }
            }

            if (project.enable_app_store_publish) {
                const ascCb = document.getElementById('enable-app-store-publish');
                if (ascCb) ascCb.checked = true;
                const ascDetails = document.getElementById('app-store-details');
                if (ascDetails) ascDetails.style.display = 'block';
            }
            if (project.app_store_key_id) {
                const keyIdEl = document.getElementById('app-store-key-id');
                if (keyIdEl) keyIdEl.value = project.app_store_key_id;
            }
            if (project.app_store_issuer_id) {
                const issuerIdEl = document.getElementById('app-store-issuer-id');
                if (issuerIdEl) issuerIdEl.value = project.app_store_issuer_id;
            }
            if (project.app_store_key_path) {
                currentAppStoreKeyPath = project.app_store_key_path;
                if (appStoreKeyUploadLabel) {
                    appStoreKeyUploadLabel.innerHTML = `
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        <span>App Store API Key Loaded</span>
                        <small class="hint">Click to change file</small>
                    `;
                    appStoreKeyUploadLabel.style.borderColor = 'var(--success)';
                    appStoreKeyUploadLabel.style.background = 'var(--success-bg)';
                }
            }

            // Handle Splash Screen settings
            if (project.enable_splash_screen !== undefined) {
                const splashCb = document.getElementById('enable-splash-screen');
                if (splashCb) {
                    splashCb.checked = project.enable_splash_screen;
                    if (splashScreenDetails) splashScreenDetails.style.display = splashCb.checked ? 'block' : 'none';
                }
            }
            if (project.splash_title) {
                const el = document.getElementById('splash-title');
                if (el) el.value = project.splash_title;
            }
            if (project.splash_subtitle) {
                const el = document.getElementById('splash-subtitle');
                if (el) el.value = project.splash_subtitle;
            }
            if (project.splash_bg_color) {
                const el = document.getElementById('splash-bg-color');
                const elHex = document.getElementById('splash-bg-color-hex');
                if (el) el.value = project.splash_bg_color;
                if (elHex) elHex.value = project.splash_bg_color;
            }
            if (project.splash_text_color) {
                const el = document.getElementById('splash-text-color');
                const elHex = document.getElementById('splash-text-color-hex');
                if (el) el.value = project.splash_text_color;
                if (elHex) elHex.value = project.splash_text_color;
            }
            if (project.splash_duration) {
                const el = document.getElementById('splash-duration');
                if (el) el.value = project.splash_duration;
            }
            if (project.splash_image_path) {
                currentSplashImagePath = project.splash_image_path;
                const splashFilename = project.splash_image_path.split(/[\\/]/).pop();
                if (splashImagePreview) {
                    splashImagePreview.innerHTML = `<img src="/uploads/${splashFilename}" alt="Splash Image" style="width: 100%; height: 100%; object-fit: contain;">`;
                    splashImagePreview.classList.add('has-icon');
                }
                if (splashImageUploadLabel) {
                    splashImageUploadLabel.innerHTML = `
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        <span>Splash Image Loaded</span>
                    `;
                }
            }

            // Handle Error Page settings
            if (project.enable_error_page !== undefined) {
                const errorCb = document.getElementById('enable-error-page');
                if (errorCb) {
                    errorCb.checked = project.enable_error_page;
                    if (errorPageDetails) errorPageDetails.style.display = errorCb.checked ? 'block' : 'none';
                }
            }
            if (project.error_title) {
                const el = document.getElementById('error-title');
                if (el) el.value = project.error_title;
            }
            if (project.error_message) {
                const el = document.getElementById('error-message');
                if (el) el.value = project.error_message;
            }
            if (project.error_button_text) {
                const el = document.getElementById('error-button-text');
                if (el) el.value = project.error_button_text;
            }
            if (project.error_bg_color) {
                const el = document.getElementById('error-bg-color');
                const elHex = document.getElementById('error-bg-color-hex');
                if (el) el.value = project.error_bg_color;
                if (elHex) elHex.value = project.error_bg_color;
            }
            if (project.error_text_color) {
                const el = document.getElementById('error-text-color');
                const elHex = document.getElementById('error-text-color-hex');
                if (el) el.value = project.error_text_color;
                if (elHex) elHex.value = project.error_text_color;
            }
            if (project.error_image_path) {
                currentErrorImagePath = project.error_image_path;
                const errFilename = project.error_image_path.split(/[\\/]/).pop();
                if (errorImagePreview) {
                    errorImagePreview.innerHTML = `<img src="/uploads/${errFilename}" alt="Error Image" style="width: 100%; height: 100%; object-fit: contain;">`;
                    errorImagePreview.classList.add('has-icon');
                }
                if (errorImageUploadLabel) {
                    errorImageUploadLabel.innerHTML = `
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        <span>Error Image Loaded</span>
                    `;
                }
            }

            // Reset build UI
            buildProgress.style.display = 'none';
            buildComplete.style.display = 'none';

            showToast('Project loaded successfully!', 'success');
        } catch (error) {
            console.error('Open error:', error);
            showToast('Error opening project: ' + error.message, 'error');
        } finally {
            openProjectBtn.disabled = false;
            openProjectBtn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
                </svg>
                <span>Open</span>
            `;
            // Reset file input
            openProjectFile.value = '';
        }
    });

    // Track icon upload path
    const originalIconChangeHandler = iconFile.onchange;
    iconFile.addEventListener('change', function() {
        // Reset the stored path when a new file is selected
        currentIconPath = null;
    });

    // Track keystore upload path
    keystoreFile.addEventListener('change', function() {
        // Reset the stored path when a new file is selected
        currentKeystorePath = null;
    });

    // Track splash & error image upload paths
    if (splashImageFile) {
        splashImageFile.addEventListener('change', function() {
            currentSplashImagePath = null;
        });
    }
    if (errorImageFile) {
        errorImageFile.addEventListener('change', function() {
            currentErrorImagePath = null;
        });
    }
});
