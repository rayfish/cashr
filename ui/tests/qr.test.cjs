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
    window: { addEventListener(name, handler) { events.set('window:' + name, handler); }, __TAURI__: { core: { invoke: async (command, args) => {
      calls.push({ command, args });
      if (command === 'unlock_with_touch_id') return scan(command, args);
      if (command.startsWith('scan_') || command === 'prepare_scan') return scan(command);
      if (command === 'pair_client') return pair(args);
      if (command === 'prompts') return prompts();
    } }, event: { listen(name, handler) { events.set('tauri:' + name, handler); return Promise.resolve(() => {}); } } } },
    document: {
      getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
      createElement() { return new Element(); },
      querySelectorAll() { return []; },
      addEventListener(name, handler) { events.set(name, handler); },
    },
    setTimeout() {}, clearTimeout() {}, setInterval() {}, requestAnimationFrame(callback) { callback(); },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../qr.js'), 'utf8'), context);
  const source = fs.readFileSync(path.join(__dirname, '../main.js'), 'utf8');
  vm.runInContext(source.slice(0, source.lastIndexOf('\nwire();')), context);
  vm.runInContext('state.tab = "scan"', context);
  return { context, calls, elements, events, get: id => context.document.getElementById(id) };
}

test('wallet errors remain available inline without a duplicate global toast', async () => {
  const view = app(async () => { throw new Error('Wallet failure fixture'); });
  let walletCall;
  view.context.window.WalletUI = { init: call => { walletCall = call; } };
  view.context.wire();
  view.get('toast').hidden = true;
  await assert.rejects(walletCall('scan_fixture', {}), /Wallet failure fixture/);
  assert.equal(view.get('toast').hidden, true);
  assert.equal(vm.runInContext('state.busy', view.context), 0);
  await assert.rejects(view.context.call('scan_fixture', {}), /Wallet failure fixture/);
  assert.equal(view.get('toast').hidden, false);
});

test('restoring a wallet sends one recovery phrase and clears secret inputs immediately', async () => {
  const view = app();
  let finish;
  const walletViews = [], walletOpens = [];
  view.context.window.WalletUI = {
    show: name => walletViews.push(name),
    open: refresh => walletOpens.push(refresh),
  };
  const calls = [];
  view.context.call = (command, args) => {
    calls.push({ command, args: JSON.parse(JSON.stringify(args)) });
    return new Promise(resolve => { finish = resolve; });
  };
  view.context.refreshAll = async () => {};
  vm.runInContext('state.unlocked = false; state.tab = "settings"', view.context);
  view.context.startWalletSetup(true, 2);
  view.get('account-label').value = 'Recovered';
  for (let i=1;i<=12;i++) view.get('recovery-word-'+i).value = i===12 ? 'about' : 'abandon';
  view.get('account-recovery-passphrase').value = 'fixture';
  view.get('account-mint').value = 'https://mint.example';
  const pending = view.context.saveAccount(true);
  await view.context.saveAccount(true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, 'import_account');
  assert.equal(calls[0].args.recovery.mnemonic.split(' ').length, 12);
  assert.equal(calls[0].args.recovery.passphrase, 'fixture');
  assert.equal(calls[0].args.recovery.mint, 'https://mint.example');
  assert.equal(calls[0].args.recovery.account, 2);
  assert.equal('secret' in calls[0].args, false);
  for (let i=1;i<=24;i++) assert.equal(view.get('recovery-word-'+i).value, '');
  assert.equal(view.get('account-recovery-passphrase').value, '');
  finish({ id: 2 });
  await pending;
  assert.equal(vm.runInContext('state.account', view.context), 2);
  assert.equal(view.get('account-new').hidden, true);
  assert.equal(vm.runInContext('state.tab', view.context), 'wallet');
  assert.deepEqual(walletViews, ['home']);
  assert.deepEqual(walletOpens, [true]);
  assert.doesNotMatch(view.get('wallet-status').textContent, /Recover tokens/);
});

test('Touch ID unlock targets the selected wallet and leaves cancellation retryable', async () => {
  let args;
  const view = app(async (command, input) => {
    assert.equal(command, 'unlock_with_touch_id');
    args = input;
    throw 'Authentication cancelled.';
  });
  vm.runInContext('state.account = 7', view.context);
  view.context.refreshStatus = async () => {};
  await view.context.unlockWithTouchId();
  assert.equal(args.account, 7);
  assert.equal('passphrase' in args, false);
  assert.equal(view.get('unlock-touch-id').disabled, false);
  assert.equal(view.get('unlock-error').hidden, false);
  assert.equal(view.get('unlock-error').textContent, 'Authentication cancelled.');
});

test('opening Cashr prompts for the selected locked wallet once and skips an unlocked wallet', async () => {
  let finish;
  const view = app(async () => new Promise(resolve => { finish = resolve; }));
  vm.runInContext('state.account = 7; state.accounts = [{id: 7}]; state.hasTouchId = true; state.tab = "wallet";', view.context);
  view.context.refreshStatus = async () => {};
  view.context.refreshAll = async () => {};
  view.context.selectTab = name => { assert.equal(name, 'wallet'); };
  const opening = view.context.start();
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(view.events.has('tauri:cashr://opened'));
  assert.equal(view.calls.filter(call => call.command === 'unlock_with_touch_id').length, 1);
  assert.equal(view.calls.find(call => call.command === 'unlock_with_touch_id').args.account, 7);
  await view.events.get('tauri:cashr://opened')();
  await view.context.unlockWithTouchId();
  assert.equal(view.calls.filter(call => call.command === 'unlock_with_touch_id').length, 1);
  vm.runInContext('state.unlockedAccounts = [7];', view.context);
  finish();
  await opening;
  assert.equal(view.calls.filter(call => call.command === 'hide_window').length, 1);
  await view.events.get('tauri:cashr://opened')();
  assert.equal(view.calls.filter(call => call.command === 'unlock_with_touch_id').length, 1);
  assert.equal(view.calls.filter(call => call.command === 'hide_window').length, 1);
  vm.runInContext('state.unlockedAccounts = [];', view.context);
  const reopening = view.events.get('tauri:cashr://opened')();
  await new Promise(resolve => setImmediate(resolve));
  finish();
  await reopening;
  assert.equal(view.calls.filter(call => call.command === 'unlock_with_touch_id').length, 2);
  assert.equal(view.calls.filter(call => call.command === 'hide_window').length, 1);
  assert.equal(vm.runInContext('state.openingWallet || state.unlocking', view.context), false);
});

test('startup unlock keeps pinned windows and pending approvals visible', async () => {
  for (const condition of ['state.pinned = true', 'state.pending = 1', 'state.paymentPending = 1']) {
    const view = app();
    vm.runInContext('state.account = 7; state.accounts = [{id: 7}]; state.hasTouchId = true; state.tab = "wallet";', view.context);
    view.context.refreshStatus = async () => {};
    view.context.refreshAll = async () => { vm.runInContext(condition, view.context); };
    view.context.selectTab = () => {};
    await view.context.start();
    assert.equal(view.calls.filter(call => call.command === 'unlock_with_touch_id').length, 1);
    assert.equal(view.calls.some(call => call.command === 'hide_window'), false, condition);
  }
});

test('startup unlock hides the window while a background wallet request is still running', async () => {
  let finishBackground;
  const view = app(async command => {
    if (command === 'scan_fixture') return new Promise(resolve => { finishBackground = resolve; });
  });
  vm.runInContext('state.account = 7; state.accounts = [{id: 7}]; state.hasTouchId = true; state.tab = "wallet";', view.context);
  view.context.refreshStatus = async () => {};
  view.context.refreshAll = async () => {};
  view.context.selectTab = () => {};
  const background = view.context.call('scan_fixture');
  try {
    await view.context.start();
    assert.equal(vm.runInContext('state.busy', view.context), 1);
    assert.equal(view.calls.filter(call => call.command === 'hide_window').length, 1);
  } finally {
    finishBackground();
    await background;
  }
  assert.equal(view.calls.filter(call => call.command === 'hide_window').length, 1);
});

test('cancelling automatic unlock waits for another explicit open or manual retry', async () => {
  const view = app(async () => { throw 'Authentication cancelled.'; });
  vm.runInContext('state.account = 7; state.accounts = [{id: 7}]; state.hasTouchId = true; state.tab = "wallet";', view.context);
  view.context.refreshStatus = async () => {};
  view.context.refreshAll = async () => {};
  view.context.selectTab = () => {};
  await view.context.start();
  await view.context.refreshAll();
  assert.equal(view.calls.filter(call => call.command === 'unlock_with_touch_id').length, 1);
  assert.equal(view.get('unlock-touch-id').disabled, false);
  assert.equal(view.get('unlock-error').textContent, 'Authentication cancelled.');
  assert.equal(view.calls.some(call => call.command === 'hide_window'), false);
  await view.events.get('tauri:cashr://opened')();
  assert.equal(view.calls.filter(call => call.command === 'unlock_with_touch_id').length, 2);
});

test('automatic unlock skips new wallets and recovery setup and offers recovery when local access is missing', async () => {
  const view = app();
  view.context.refreshStatus = async () => {};
  view.context.refreshAll = async () => {};
  view.context.selectTab = () => {};
  await view.context.openWallet();
  vm.runInContext('state.account = 7; state.accounts = [{id: 7}]; state.tab = "setup"; state.hasTouchId = true;', view.context);
  await view.context.openWallet();
  vm.runInContext('state.tab = "wallet"; state.hasTouchId = false;', view.context);
  let recoveryFocused = false;
  view.get('unlock-recover').focus = () => { recoveryFocused = true; };
  await view.context.openWallet();
  assert.equal(recoveryFocused, true);
  assert.equal(view.calls.filter(call => call.command === 'unlock_with_touch_id').length, 0);
});

test('pasting a phrase fills numbered fields from the beginning and normalizes whitespace', () => {
  const view = app();
  const paste = text => ({ preventDefault() {}, clipboardData: { getData: () => text } });
  view.context.pasteRecoveryWords(paste('  ABANDON\n'.repeat(11) + '\tABOUT  '), 6);
  assert.equal(view.get('recovery-count').value, '12');
  for (let i=1;i<=12;i++) assert.equal(view.get('recovery-word-'+i).value, i===12 ? 'about' : 'abandon');
  view.context.pasteRecoveryWords(paste('zoo '.repeat(23)+'vote'), 3);
  assert.equal(view.get('recovery-count').value, '24');
  assert.equal(view.get('recovery-slot-24').hidden, false);
  assert.equal(view.get('recovery-word-24').value, 'vote');
  view.context.pasteRecoveryWords(paste('abandon '.repeat(11)+'about'), 0);
  assert.equal(view.get('recovery-word-24').value, '');
  assert.equal(view.get('recovery-slot-24').hidden, true);
});

test('partial pastes start at the focused word and overflow is rejected without dropping words', () => {
  const view = app();
  const paste = text => ({ preventDefault() {}, clipboardData: { getData: () => text } });
  view.context.pasteRecoveryWords(paste('abandon about'), 4);
  assert.equal(view.get('recovery-word-5').value, 'abandon');
  assert.equal(view.get('recovery-word-6').value, 'about');
  view.context.pasteRecoveryWords(paste('one two three'), 11);
  assert.equal(view.get('recovery-word-12').value, '');
  assert.match(view.get('account-error').textContent, /complete 12- or 24-word phrase/);
});

test('incomplete phrases cannot start import', async () => {
  const view = app();
  view.context.startWalletSetup(true);
  view.get('recovery-word-1').value = 'abandon';
  await view.context.saveAccount(true);
  assert.equal(view.calls.length, 0);
  assert.equal(view.get('account-error').textContent, 'Enter all recovery words.');
});

test('cancelled Touch ID restores the entered words only while the same setup remains open', async () => {
  const view = app();
  view.context.startWalletSetup(true);
  let reject;
  view.context.call = () => new Promise((_, fail) => { reject = fail; });
  const fill = () => { for (let i=1;i<=12;i++) view.get('recovery-word-'+i).value = i===12 ? 'about' : 'abandon'; };
  fill();
  let pending = view.context.saveAccount(true);
  assert.equal(view.get('recovery-word-1').value, '');
  reject('Authentication cancelled.');
  await pending;
  assert.equal(view.get('recovery-word-1').value, 'abandon');
  assert.equal(view.get('recovery-word-12').value, 'about');
  assert.equal(view.get('account-import').disabled, false);
  pending = view.context.saveAccount(true);
  view.context.selectTab('wallet');
  reject('Authentication was interrupted. Try again.');
  await pending;
  for (let i=1;i<=24;i++) assert.equal(view.get('recovery-word-'+i).value, '');
});

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
  assert.equal(view.get('lightning-remove').hidden, true);
});

test('a late profile lookup cannot replace a typed address or another account', async () => {
  const view = app();
  view.context.wire();
  vm.runInContext('state.accounts = [{id:1,label:"First"},{id:2,label:"Second"}]; state.account=1', view.context);
  view.context.renderLightningAddress();
  let finish;
  view.context.call = () => new Promise(resolve => { finish = resolve; });
  let pending = view.context.findLightningAddress();
  view.get('lightning-address').value = 'manual@example.com';
  view.get('lightning-address').oninput();
  finish('published@minibits.cash');
  await pending;
  assert.equal(view.get('lightning-address').value, 'manual@example.com');
  view.get('lightning-address').value = '';
  view.get('lightning-address').oninput();
  pending = view.context.findLightningAddress();
  vm.runInContext('state.account=2', view.context);
  view.context.renderLightningAddress();
  finish('first@minibits.cash');
  await pending;
  assert.equal(view.get('lightning-address').value, '');
});

test('profile lookup fills a draft without saving or replacing an existing address', async () => {
  const view = app();
  vm.runInContext('state.accounts=[{id:1,label:"First"}]; state.account=1', view.context);
  view.context.renderLightningAddress();
  const calls = [];
  view.context.call = async command => { calls.push(command); return 'alice@minibits.cash'; };
  await view.context.findLightningAddress();
  assert.equal(view.get('lightning-address').value, 'alice@minibits.cash');
  view.context.renderLightningAddress();
  await view.context.findLightningAddress();
  assert.equal(view.get('lightning-address').value, 'alice@minibits.cash');
  assert.deepEqual(calls, ['find_lightning_address']);
});

test('a newly selected locked account stays visibly locked while another account is unlocked', () => {
  const view = app();
  vm.runInContext('state.accounts = [{ id: 1, label: "Personal", npub: "npub1" }, { id: 2, label: "New", npub: "npub2" }]; state.account = 2; state.unlocked = true; state.unlockedAccounts = [1]', view.context);
  view.context.renderAccountPicker();
  view.context.renderAccountCard();
  view.context.renderUnlock();
  assert.equal(view.get('account-picker').children[0].textContent, 'Personal');
  assert.equal(view.get('account-picker').children[1].textContent, 'New');
  const head = view.get('account-card').children.find(node => node.className === 'card-head');
  assert.equal(head.children.find(node => node.className.startsWith('pill')).textContent, 'Locked');
  assert.equal(view.get('unlock').hidden, false);
  vm.runInContext('state.unlockedAccounts = [1, 2]', view.context);
  view.context.renderUnlock();
  assert.equal(view.get('unlock').hidden, true);
});

test('recognizes QR types and offers review actions without executing payments', () => {
  const { context } = app();
  const describe = context.CashrQR.describe;
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
    assert.equal(describe(value).action, title === 'Cashu token' ? 'receive' : title === 'Lightning invoice' ? 'pay' : undefined);
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
  assert.equal(vm.runInContext('state.tab', view.context), 'wallet');
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
  assert.match(view.get('scan-status').textContent, /paste an image/);
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

test('NWC approvals show amount and fees, require a click, and cannot submit twice', async () => {
  const view = app();
  vm.runInContext('state.unlockedAccounts = [1]', view.context);
  const prompt = { id: 'request', connection: 'connection', account: 1, account_label: 'Personal', app: '<img src=x>', mint: 'https://mint.example', amount: 21, max_fee: 2, maximum: 23, destination: 'a'.repeat(66), expiry: 2000000000 };
  let finish; const answers = [];
  view.context.call = async (command, args) => {
    if (command === 'nwc_pending') return [prompt];
    if (command === 'nwc_answer') { answers.push(args); return new Promise(resolve => { finish = resolve; }); }
  };
  await view.context.refreshPaymentPrompts();
  const row = view.get('nwc-prompts').children[0];
  assert.match(row.children[0].textContent, /<img src=x>/);
  assert.equal(row.children[1].textContent, '21 sats');
  assert.match(row.children[2].textContent, /Max fee 2 sats · Total up to 23 sats/);
  assert.equal(answers.length, 0);
  const buttons = row.children[5];
  assert.equal(buttons.children.length, 2);
  const click = buttons.children[0].onclick();
  await buttons.children[0].onclick();
  assert.equal(answers.length, 1);
  assert.equal(answers[0].allow, true);
  finish(); await click;
});

test('NWC approvals disable paying a locked account and allow declining it', async () => {
  const view = app(); const answers = [];
  view.context.call = async (command, args) => {
    if (command === 'nwc_pending') return [{ id: 'request', account: 1, app: 'Jumble', amount: 21, max_fee: 1, maximum: 22, destination: 'a'.repeat(66) }];
    if (command === 'nwc_answer') answers.push(args);
  };
  await view.context.refreshPaymentPrompts();
  const buttons = view.get('nwc-prompts').children[0].children[5];
  assert.equal(buttons.children[0].disabled, true);
  await buttons.children[1].onclick();
  assert.equal(answers[0].allow, false);
});
