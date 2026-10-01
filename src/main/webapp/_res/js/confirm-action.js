/* Confirmation step for destructive row actions (delete, disable).
 *
 * The trigger carries the wording, so each page keeps its own phrasing:
 *   data-confirm        the question, e.g. 'Delete "web-01"? ...'
 *   data-confirm-title  dialog heading (default "Confirm")
 *   data-confirm-label  confirm button text (default "Delete")
 *
 * A page wraps the body of its existing click handler in confirmAction(), so the
 * action runs only after the dialog is confirmed.
 */
(function (root) {
    'use strict';

    var pending = null;
    var modal = null;
    var opener = null;

    function dialog() {
        var element = document.getElementById('confirm_dialog');
        if (!element) {
            return null;
        }
        if (!modal) {
            modal = bootstrap.Modal.getOrCreateInstance(element);
            $('#confirm_btn').on('click', function () {
                var run = pending;
                pending = null;
                modal.hide();
                if (run) {
                    run();
                }
            });
            // Cancel, Escape and the backdrop all leave the pending action unrun.
            $(element).on('hidden.bs.modal', function () {
                pending = null;
                if (opener && opener.isConnected) opener.focus();
                opener = null;
            });
            // Open on Cancel rather than on the destructive button.
            $(element).on('shown.bs.modal', function () {
                $('#confirm_cancel_btn').trigger('focus');
            });
        }
        return element;
    }

    root.confirmAction = function (trigger, onConfirm) {
        var button = $(trigger);
        var message = button.attr('data-confirm') || 'This cannot be undone.';

        // Without the dialog fragment, still ask rather than delete silently.
        if (!dialog()) {
            if (root.confirm(message)) {
                onConfirm();
            }
            return;
        }

        $('#confirm_title').text(button.attr('data-confirm-title') || 'Confirm');
        $('#confirm_message').text(message);
        $('#confirm_btn').text(button.attr('data-confirm-label') || 'Delete');
        opener = trigger;
        pending = onConfirm;
        modal.show();
    };
}(window));
