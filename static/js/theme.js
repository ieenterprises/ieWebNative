/**
 * ieWebNative Theme Controller
 * Supports Day Mode (☀️), Moon Light Mode (🌙), and Automatic Day/Night adaptation (🌓)
 * Switches automatically as the day progresses (Day: 06:00-18:59, Moon light: 19:00-05:59).
 */

(function (window) {
    'use strict';

    const STORAGE_KEY = 'iewebnative_theme';

    function getTimeBasedTheme() {
        const hour = new Date().getHours();
        return (hour >= 6 && hour < 19) ? 'light' : 'dark';
    }

    function getStoredPreference() {
        return localStorage.getItem(STORAGE_KEY) || 'auto';
    }

    function resolveEffectiveTheme(pref) {
        if (pref === 'light' || pref === 'dark') {
            return pref;
        }
        return getTimeBasedTheme();
    }

    function applyTheme(pref) {
        const effective = resolveEffectiveTheme(pref);
        document.documentElement.setAttribute('data-theme', effective);
        document.documentElement.setAttribute('data-theme-pref', pref);
        updateToggleButtons(pref, effective);
        window.dispatchEvent(new CustomEvent('themechange', {
            detail: { preference: pref, effective: effective }
        }));
    }

    function updateToggleButtons(pref, effective) {
        const buttons = document.querySelectorAll('.theme-toggle-btn');
        buttons.forEach(btn => {
            const iconEl = btn.querySelector('.theme-icon') || btn;
            const labelEl = btn.querySelector('.theme-label');

            let iconHtml = '';
            let titleText = '';

            if (pref === 'auto') {
                if (effective === 'dark') {
                    iconHtml = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>';
                    titleText = 'Moon Light (Auto: adapts to time of day)';
                } else {
                    iconHtml = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>';
                    titleText = 'Day Light (Auto: adapts to time of day)';
                }
            } else if (pref === 'dark') {
                iconHtml = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>';
                titleText = 'Moon Light Mode (Click to switch to Day mode)';
            } else {
                iconHtml = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>';
                titleText = 'Day Mode (Click to switch to Moon Light)';
            }

            if (btn.querySelector('.theme-icon')) {
                btn.querySelector('.theme-icon').innerHTML = iconHtml;
            } else {
                btn.innerHTML = iconHtml;
            }
            btn.setAttribute('title', titleText);
            btn.setAttribute('aria-label', titleText);

            if (labelEl) {
                labelEl.textContent = effective === 'dark' ? 'Moon' : 'Day';
            }
        });
    }

    function cycleTheme() {
        const currentPref = getStoredPreference();
        let nextPref = 'light';

        if (currentPref === 'auto') {
            const effective = getTimeBasedTheme();
            nextPref = effective === 'light' ? 'dark' : 'light';
        } else if (currentPref === 'light') {
            nextPref = 'dark';
        } else {
            nextPref = 'auto';
        }

        localStorage.setItem(STORAGE_KEY, nextPref);
        applyTheme(nextPref);

        if (typeof window.showToast === 'function') {
            const names = {
                'auto': 'Auto Mode (Adapts to Day & Moon light)',
                'light': 'Day Mode (Sun Light)',
                'dark': 'Moon Light Mode (Night Dark)'
            };
            window.showToast('Theme: ' + (names[nextPref] || nextPref), 'info');
        }
    }

    const currentPref = getStoredPreference();
    applyTheme(currentPref);

    setInterval(function() {
        const pref = getStoredPreference();
        if (pref === 'auto') {
            const effective = getTimeBasedTheme();
            if (document.documentElement.getAttribute('data-theme') !== effective) {
                applyTheme('auto');
            }
        }
    }, 60000);

    document.addEventListener('DOMContentLoaded', function() {
        applyTheme(getStoredPreference());

        document.addEventListener('click', function(e) {
            const btn = e.target.closest('.theme-toggle-btn');
            if (btn) {
                e.preventDefault();
                cycleTheme();
            }
        });
    });

    window.ThemeService = {
        getPreference: getStoredPreference,
        getEffectiveTheme: function() { return resolveEffectiveTheme(getStoredPreference()); },
        setTheme: function(pref) {
            localStorage.setItem(STORAGE_KEY, pref);
            applyTheme(pref);
        },
        toggle: cycleTheme
    };

})(window);
