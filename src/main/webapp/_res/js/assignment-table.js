/* Shared behaviour for the profile assignment tables (systems and users):
 * a select-all checkbox, a live count, and client-side sorting that keeps
 * unsaved checkbox changes intact.
 */
$(function () {
    var form = $('.assignment-form');
    if (!form.length) return;

    var choices = form.find('input[type="checkbox"][name$="SelectId"]');
    var selectAll = $('#assignment-select-all');
    var label = form.data('item-label') || 'item';

    function updateSelection() {
        var selected = choices.filter(':checked').length;
        selectAll.prop('checked', choices.length > 0 && selected === choices.length)
            .prop('indeterminate', selected > 0 && selected < choices.length);
        $('#assignment-count').text(selected + ' of ' + choices.length + ' '
            + (choices.length === 1 ? label : label + 's') + ' selected');
    }

    selectAll.on('change', function () {
        choices.prop('checked', this.checked);
        updateSelection();
    });
    choices.on('change', updateSelection);

    // Sort in place so pending checkbox changes survive reordering.
    $('.assignment-sort').on('click', function () {
        var header = $(this).closest('th');
        var descending = header.attr('aria-sort') === 'ascending';
        var column = header.index();
        var rows = form.find('tbody tr').get();
        rows.sort(function (a, b) {
            var result = a.cells[column].textContent.trim().localeCompare(
                b.cells[column].textContent.trim(), undefined, {numeric: true, sensitivity: 'base'});
            return descending ? -result : result;
        });
        form.find('th[aria-sort]').attr('aria-sort', 'none');
        header.attr('aria-sort', descending ? 'descending' : 'ascending');
        form.find('tbody').append(rows);
    });

    updateSelection();
});
