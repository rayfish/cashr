const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function app(scan = async () => [], pair = async () => ({ client_name: 'Test client', client_public_key: 'a'.repeat(64) }), prompts = async () => []) {
  class Element {
    constructor() { this.children = []; this.attributes = {}; this.hidden = false; this.value = ''; this.textContent = ''; this.classList = { toggle() {}, add() {}, remove() {} }; }
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren(...nodes) { this.children = nodes; }
    setAttribute(name, value) { this.attributes[name] = value; }
    focus() {}
  }
  const elements = new Map();
  const events = new Map();
  const calls = [];
  const context = vm.createContext({
    window: { __TAURI__: { core: { invoke: async (command, args) => {
      calls.push({ command, args });
      if (command.startsWith('scan_') || command === 'prepare_scan') return scan(command);
      if (command === 'pair_client') return pair(args);
      if (command === 'prompts') return prompts();
    } }, event: { listen() {} } } },
    document: {
      getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
      createElement() { return new Element(); },
      querySelectorAll() { return []; },
      addEventListener(name, handler) { events.set(name, handler); },
    },
    setTimeout() {}, clearTimeout() {}, setInterval() {}, requestAnimationFrame(callback) { callback(); },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../qr.js'), 'utf8'), context);
  const source = fs.readFileSync(path.join(__dirname, '../main.js'), 'utf8').replace(/wire\(\);\s*refreshAll\(\);\s*$/, '');
  vm.runInContext(source, context);
  vm.runInContext('state.tab = "scan"', context);
  return { context, calls, elements, events, get: id => context.document.getElementById(id) };
}

test('Lightning address drafts survive refreshes and switch with the selected account', () => {
  const view = app();
  vm.runInContext('state.accounts = [{ id: 1, label: "Personal", lightning_address: "alice@example.com" }, { id: 2, label: "Work", lightning_address: null }]; state.account = 1', view.context);
  view.context.wire();
  view.context.renderLightningAddress();
  assert.equal(view.get('lightning-address').value, 'alice@example.com');
  view.get('lightning-address').value = 'new@example.com';
  view.get('lightning-address').oninput();
  view.context.renderLightningAddress();
  assert.equal(view.get('lightning-address').value, 'new@example.com');
  vm.runInContext('state.account = 2', view.context);
  view.context.renderLightningAddress();
  assert.equal(view.get('lightning-address').value, '');
  assert.equal(view.get('lightning-account').textContent, 'For Work');
  assert.equal(view.get('lightning-remove').hidden, true);
});

test('a newly selected locked account stays visibly locked while another account is unlocked', () => {
  const view = app();
  vm.runInContext('state.accounts = [{ id: 1, label: "Personal", npub: "npub1" }, { id: 2, label: "New", npub: "npub2" }]; state.account = 2; state.unlocked = true; state.unlockedAccounts = [1]', view.context);
  view.context.renderAccountPicker();
  view.context.renderAccountCard();
  view.context.renderUnlock();
  assert.equal(view.get('account-picker').children[0].textContent, 'Personal · Unlocked');
  assert.equal(view.get('account-picker').children[1].textContent, 'New · Locked');
  const head = view.get('account-card').children.find(node => node.className === 'card-head');
  assert.equal(head.children.find(node => node.className.startsWith('pill')).textContent, 'Locked');
  assert.equal(view.get('unlock').hidden, false);
  vm.runInContext('state.unlockedAccounts = [1, 2]', view.context);
  view.context.renderUnlock();
  assert.equal(view.get('unlock').hidden, true);
});

test('recognizes pairing, wallet, payment and secret codes without payment actions', () => {
  const { context } = app();
  const describe = context.ByrgiQR.describe;
  assert.equal(describe('nostrconnect://abc?secret=test').action, 'pair');
  for (const [value, title] of [
    ['bunker://abc', 'Nostr signer connection'],
    ['nostr+walletconnect://abc?secret=test', 'Lightning wallet connection'],
    ['cashu:cashuBabcdef', 'Cashu token'],
    ['lightning:lnbc210n1qqqqqq', 'Lightning invoice'],
    ['LNBC1QQQQQQ', 'Lightning invoice'],
    ['lnurl1qqqqqq', 'LNURL link'],
    ['nostr:nsec1secret', 'Private key'],
    ['https://example.com', 'QR content'],
    ['<script>alert(1)</script>', 'QR content'],
  ]) {
    assert.equal(describe(value).title, title);
    assert.equal(describe(value).action, undefined);
  }
});

test('scanning offers Connect without pairing automatically or exposing connection secrets', async () => {
  const uri = 'nostrconnect://' + 'a'.repeat(64) + '?relay=wss://example.com&secret=test';
  const view = app(async () => [uri, '<img src=x onerror=alert(1)>']);
  await view.context.scanQR('clipboard');
  const cards = view.get('scan-results').children;
  assert.equal(cards.length, 2);
  const content = cards[1].children[2];
  assert.equal(content.hidden, true);
  assert.equal(content.value, '');
  cards[1].children[3].children[0].onclick();
  assert.equal(content.value, '<img src=x onerror=alert(1)>');
  assert.equal(cards[0].children.length, 3);
  assert.equal(cards[0].children[2].textContent, 'Connect');
  assert.equal(view.get('scan-input').hidden, true);
  assert.equal(view.calls.some(c => c.command === 'pair_client'), false);
  vm.runInContext('state.account = 1; state.unlocked = true', view.context);
  view.context.refreshAll = async () => {};
  await cards[0].children[2].onclick();
  assert.equal(view.calls.filter(c => c.command === 'pair_client').length, 1);
  assert.equal(view.calls.find(c => c.command === 'pair_client').args.uri, uri);
  assert.equal(view.get('scan-results').children.length, 0);
  assert.equal(vm.runInContext('state.tab', view.context), 'clients');
});

test('cancellation and errors leave the scanner ready to retry', async () => {
  const cancelled = app(async () => null);
  await cancelled.context.scanQR('screen');
  assert.equal(cancelled.get('scan-status').textContent, 'Scan cancelled.');
  assert.equal(cancelled.get('scan-screen').disabled, false);
  const failed = app(async () => { throw new Error('No readable QR code found.'); });
  await failed.context.scanQR('clipboard');
  assert.match(failed.get('scan-status').textContent, /No readable QR/);
  assert.equal(failed.get('scan-clipboard').disabled, false);
});

test('duplicate scans are suppressed and leaving the panel discards late results', async () => {
  let finish;
  const view = app(() => new Promise(resolve => { finish = resolve; }));
  const pending = view.context.scanQR('clipboard');
  await view.context.scanQR('screen');
  assert.equal(view.calls.filter(c => c.command.startsWith('scan_')).length, 1);
  view.context.selectTab('home');
  finish(['cashuBabcdef']);
  await pending;
  assert.equal(view.get('scan-results').children.length, 0);
  assert.equal(view.get('scan-status').textContent, '');
});

test('Cmd+V scans only from the scanner panel and preserves text-field paste', async () => {
  const view = app(async () => ['test']);
  view.context.wire();
  const paste = view.events.get('paste');
  let prevented = 0;
  paste({ target: { matches: () => true }, preventDefault() { prevented++; } });
  assert.equal(prevented, 0);
  paste({ target: { matches: () => false }, preventDefault() { prevented++; } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(prevented, 1);
  assert.equal(view.calls.filter(c => c.command === 'scan_clipboard').length, 1);
  view.context.selectTab('home');
  paste({ target: { matches: () => false }, preventDefault() { prevented++; } });
  assert.equal(prevented, 1);
});

test('Escape dismisses scan results before closing the window', () => {
  const view = app();
  view.context.wire();
  view.context.renderScannedCodes(['secret test']);
  let prevented = false;
  view.events.get('keydown')({ key: 'Escape', preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(view.get('scan-results').children.length, 0);
  assert.equal(vm.runInContext('state.tab', view.context), 'home');
  assert.equal(view.calls.some(c => c.command === 'hide_window'), false);
});


test('opening Scan QR requests permission before capturing and denial leaves clipboard available', async () => {
  const view = app(async command => command === 'prepare_scan' ? false : ['test']);
  vm.runInContext('state.tab = "home"', view.context);
  view.context.toggleScanner();
  assert.equal(vm.runInContext('state.tab', view.context), 'scan');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(view.calls.filter(c => c.command === 'prepare_scan').length, 1);
  assert.equal(view.calls.some(c => c.command === 'scan_screen'), false);
  assert.match(view.get('scan-status').textContent, /You can still paste/);
  assert.equal(view.get('scan-clipboard').disabled, false);
  await view.context.scanQR('clipboard');
  assert.equal(view.get('scan-results').children.length, 1);
});

test('Connect requires unlock, prevents duplicate pairing, and allows retry after failure', async () => {
  let reject;
  const view = app(async () => ['nostrconnect://abc'], () => new Promise((_, fail) => { reject = fail; }));
  await view.context.scanQR('clipboard');
  const button = view.get('scan-results').children[0].children[2];
  await button.onclick();
  assert.equal(view.calls.some(c => c.command === 'pair_client'), false);
  vm.runInContext('state.account = 1; state.unlocked = true', view.context);
  const pending = button.onclick();
  await button.onclick();
  assert.equal(view.calls.filter(c => c.command === 'pair_client').length, 1);
  reject(new Error('Pairing expired'));
  await pending;
  assert.equal(button.disabled, false);
  assert.equal(button.textContent, 'Connect');
  assert.equal(view.get('scan-results').children.length, 1);
});


test('approval previews render as text and preserve expanded details across polling', async () => {
  let pending = [{
    id: 'request-1', client_name: 'Test app', account_label: 'Personal',
    detail: 'publish a note', method: 'sign_event', kind: 1, kind_name: 'Note',
    client_public_key: 'a'.repeat(64),
    preview: { explanation: 'The app decides whether to publish it.', fields: [], content: '<script>alert(1)</script>' },
  }];
  const { context, get } = app(undefined, undefined, async () => pending);
  await context.refreshPrompts();
  const row = get('prompts').children[0];
  assert.equal(row.children[0].textContent, 'Test app wants to publish a note');
  const preview = row.children.find(node => node.className === 'request-preview');
  assert.equal(preview.textContent, '<script>alert(1)</script>');
  assert.equal(preview.children.length, 0);
  const details = row.children.find(node => node.className === 'request-details');
  details.open = true;
  await context.refreshPrompts();
  assert.equal(get('prompts').children[0], row);
  assert.equal(details.open, true);
  pending = [];
  await context.refreshPrompts();
  assert.equal(get('prompts').hidden, true);
  assert.equal(get('prompts').children.length, 0);
});
