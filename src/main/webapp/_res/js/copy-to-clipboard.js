/* Copy button for key material.
 *
 * The keys on this page are long base64 strings that have to be reproduced exactly on a
 * remote host - hand-selecting one out of a <pre> is how they end up truncated or with a
 * stray newline, which then fails with an unhelpful error on the far end.
 *
 * Markup: <button class="copy_btn" data-copy-from="<element id>">Copy</button>
 */
(function () {
    'use strict';

    function flash(button, message) {
        var original = button.getAttribute('data-original-label') || button.textContent;
        button.setAttribute('data-original-label', original);
        button.textContent = message;
        button.disabled = true;
        setTimeout(function () {
            button.textContent = original;
            button.disabled = false;
        }, 1500);
    }

    function legacyCopy(text) {
        // navigator.clipboard needs a secure context, and Bastillion is reachable over plain
        // HTTP behind a TLS-terminating proxy - so this path is ordinary, not exotic.
        var area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        var ok = false;
        try {
            ok = document.execCommand('copy');
        } catch (e) {
            ok = false;
        }
        document.body.removeChild(area);
        return ok;
    }

    document.addEventListener('click', function (event) {
        var button = event.target.closest ? event.target.closest('.copy_btn') : null;
        if (!button) {
            return;
        }
        event.preventDefault();
        var source = document.getElementById(button.getAttribute('data-copy-from'));
        if (!source) {
            return;
        }
        var text = (source.textContent || '').trim();

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(function () {
                flash(button, 'Copied');
            }, function () {
                flash(button, legacyCopy(text) ? 'Copied' : 'Press Ctrl+C');
            });
            return;
        }
        flash(button, legacyCopy(text) ? 'Copied' : 'Press Ctrl+C');
    });
}());
