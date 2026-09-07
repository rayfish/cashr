const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const balance = { balance: 100, pending: 0, transactions: [], funding_invoice: null };
function app(backend = async () => balance) {
  class Element {
    constructor() { this.children = []; this.value = ''; this.textContent = ''; this.hidden = false; }
    append(...children) { this.children.push(...children); }
    replaceChildren() { this.children = []; this.textContent = ''; }
    focus() {}
  }
  const elements = new Map();
  const get = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const context = vm.createContext({ window: {}, document: { getElementById: get, querySelectorAll: () => [...elements.values()], createElement: () => new Element() } });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../wallet.js'), 'utf8'), context);
  const calls = [];
  const ui = context.window.WalletUI;
  ui.init(async (command, args) => { calls.push({ command, args }); return backend(command, args); });
  ui.sync({ id: 1, label: 'Personal' }, true);
  return { ui, get, calls };
}

test('payment needs a review and duplicate confirmations send only once', async () => {
  let finish;
  const view = app(async command => {
    if (command === 'wallet_review') return { quote: 'q', amount: 10, max_fee: 2, maximum: 12, expiry: 2000000000, destination: '<script>provider</script>' };
    if (command === 'wallet_pay') return new Promise(resolve => { finish = resolve; });
    return balance;
  });
  await view.get('wallet-confirm').onclick();
  assert.equal(view.calls.length, 0);
  await view.get('wallet-open').onclick();
  view.get('wallet-request').value = 'lnbc…';
  view.get('wallet-pay-form').onsubmit({ preventDefault() {} });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(view.calls.some(call => call.command === 'wallet_pay'), false);
  assert.equal(view.get('wallet-destination').textContent, '<script>provider</script>');
  assert.equal(view.get('wallet-destination').children.length, 0);
  const pending = view.get('wallet-confirm').onclick();
  await view.get('wallet-confirm').onclick();
  assert.equal(view.calls.filter(call => call.command === 'wallet_pay').length, 1);
  assert.equal(view.calls.at(-1).args.account, 1);
  finish(balance);
  await pending;
  assert.equal(view.get('wallet-review').hidden, true);
});

test('switching account discards a late response and clears invoice and review state', async () => {
  let finish;
  const view = app(() => new Promise(resolve => { finish = resolve; }));
  const pending = view.get('wallet-open').onclick();
  view.get('wallet-token').value = 'cashu-secret';
  view.ui.sync({ id: 2, label: 'Work' }, true);
  finish(balance);
  await pending;
  assert.equal(view.get('wallet-account').textContent, 'For Work');
  assert.equal(view.get('wallet-balance').textContent, '— sats');
  assert.equal(view.get('wallet-token').value, '');
  assert.equal(view.get('wallet-review').hidden, true);
});

test('locked wallets refuse operations and preserve no visible balance', async () => {
  const view = app();
  await view.get('wallet-open').onclick();
  assert.equal(view.get('wallet-balance').textContent, '100 sats');
  const previousCalls = view.calls.length;
  view.ui.sync({ id: 1, label: 'Personal' }, false);
  await view.get('wallet-open').onclick();
  assert.equal(view.calls.length, previousCalls);
  assert.equal(view.get('wallet-balance').textContent, '— sats');
  assert.equal(view.get('wallet-actions').hidden, true);
});

test('failed payments do not retain an approval for a blind retry', async () => {
  const view = app(async command => {
    if (command === 'wallet_review') return { quote: 'q', amount: 10, max_fee: 2, maximum: 12, expiry: 2000000000, destination: 'provider' };
    if (command === 'wallet_pay') throw new Error('Refresh before retrying.');
    return balance;
  });
  await view.get('wallet-open').onclick();
  view.get('wallet-pay-form').onsubmit({ preventDefault() {} });
  await new Promise(resolve => setImmediate(resolve));
  await view.get('wallet-confirm').onclick();
  await view.get('wallet-confirm').onclick();
  assert.equal(view.calls.filter(call => call.command === 'wallet_pay').length, 1);
  assert.match(view.get('wallet-status').textContent, /Refresh before retrying/);
});

test('import clears seed fields and preserves the imported wallet when recovery is unavailable', async () => {
  const view = app(async command => {
    if (command === 'wallet_import') return { ...balance, mint: 'https://mint.example' };
    if (command === 'wallet_restore') throw new Error('offline');
    if (command === 'wallet_list') return { active: 'imported', wallets: [{ id: 'original', label: 'Original wallet' }, { id: 'imported', label: 'Imported wallet' }] };
    return balance;
  });
  view.get('wallet-import-seed').value = 'seed fixture';
  view.get('wallet-import-passphrase').value = 'passphrase fixture';
  view.get('wallet-import-mint').value = 'https://mint.example';
  view.get('wallet-import-form').onsubmit({ preventDefault() {} });
  assert.equal(view.get('wallet-import-seed').value, '');
  assert.equal(view.get('wallet-import-passphrase').value, '');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(view.calls.find(call => call.command === 'wallet_import').args.account, 1);
  assert.equal(view.get('wallet-picker').value, 'imported');
  assert.equal(view.get('wallet-picker').hidden, false);
  assert.match(view.get('wallet-mint').textContent, /mint.example/);
  assert.match(view.get('wallet-status').textContent, /Wallet imported.*retry/);
  assert.equal(view.calls.some(call => call.command === 'wallet_pay'), false);
});
