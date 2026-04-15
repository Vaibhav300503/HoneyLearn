/**
 * Browser-side Fingerprinting Module.
 * Collects non-invasive browser signals and sends them to the server.
 * Embedded in honeypot pages to enrich attacker fingerprints.
 */
(function() {
    function collectFingerprint() {
        const fp = {};

        // Timezone
        try {
            fp.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
            fp.timezoneOffset = new Date().getTimezoneOffset();
        } catch(e) { fp.timezone = 'unknown'; }

        // Language
        fp.language = navigator.language || navigator.userLanguage || 'unknown';
        fp.languages = navigator.languages ? Array.from(navigator.languages) : [];

        // Screen
        fp.screenWidth = screen.width;
        fp.screenHeight = screen.height;
        fp.colorDepth = screen.colorDepth;
        fp.pixelRatio = window.devicePixelRatio || 1;

        // Platform
        fp.platform = navigator.platform || 'unknown';
        fp.hardwareConcurrency = navigator.hardwareConcurrency || 0;
        fp.maxTouchPoints = navigator.maxTouchPoints || 0;

        // Canvas fingerprint
        try {
            var canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            var ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(0, 0, 200, 50);
            ctx.fillStyle = '#069';
            ctx.fillText('Fingerprint', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('Canvas', 4, 35);
            fp.canvasHash = hashCode(canvas.toDataURL());
        } catch(e) {
            fp.canvasHash = 'unavailable';
        }

        // WebGL renderer
        try {
            var gl = document.createElement('canvas').getContext('webgl');
            if (gl) {
                var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    fp.webglVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                    fp.webglRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                }
            }
        } catch(e) {}

        // Do Not Track
        fp.doNotTrack = navigator.doNotTrack || 'unset';

        // Cookie enabled
        fp.cookieEnabled = navigator.cookieEnabled;

        return fp;
    }

    function hashCode(str) {
        var hash = 0;
        for (var i = 0; i < str.length; i++) {
            var char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return hash.toString(16);
    }

    // Send fingerprint to server (silently, no error handling visible)
    try {
        var fp = collectFingerprint();
        fetch('/api/fingerprint', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(fp)
        }).catch(function() {});
    } catch(e) {}
})();
