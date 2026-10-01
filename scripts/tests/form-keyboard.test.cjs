const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('src/main/webapp/_res/inc/header.html', 'utf8');
const start = source.indexOf("            $('form input:not(");
const end = source.indexOf('// Native buttons', start);
function setup() {
    let handler;
    vm.runInNewContext(source.slice(start, end), {
        $: () => ({on: (event, callback) => { handler = callback; }})
    });
    return handler;
}
test('Enter uses native validated submission exactly once', () => {
    let submits = 0;
    let prevented = 0;
    setup().call({form: {requestSubmit: () => submits++}}, {
        key: 'Enter', preventDefault: () => prevented++
    });
    assert.equal(submits, 1);
    assert.equal(prevented, 1);
});
test('composition and ordinary typing never submit a form', () => {
    const handler = setup();
    for (const event of [
        {key: 'Enter', isComposing: true},
        {key: 'Enter', originalEvent: {isComposing: true}},
        {key: 'a'}
    ]) {
        handler.call({form: {requestSubmit: () => assert.fail('Unexpected submission')}}, {
            ...event, preventDefault: () => assert.fail('Typing intercepted')
        });
    }
});
