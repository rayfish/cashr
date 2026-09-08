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
    setAttribute(name, value) { this[name] = value; }
    getContext() { return { fillStyle: '', fillRect() {} }; }
  }
  const elements = new Map();
  const timers = [], events = new Map();
  const get = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const context = vm.createContext({ window: { addEventListener: (name, handler) => events.set(name, handler) }, setTimeout: callback => { timers.push(callback); return timers.length; }, clearTimeout: id => { if (id) timers[id - 1] = null; }, document: { addEventListener: (name, handler) => events.set(name, handler), getElementById: get, querySelectorAll: selector => [...elements.values()].filter(element => selector !== '[data-wallet-view]' || element.dataset?.walletView), createElement: () => new Element(), createElementNS: () => new Element() } });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../wallet.js'), 'utf8'), context);
  const calls = [];
  const ui = context.window.WalletUI;
  ui.init(async (command, args) => { calls.push({ command, args }); return backend(command, args); });
  ui.sync({ id: 1, label: 'Personal' }, true);
  return { ui, get, calls, timers, events };
}

test('provider receiving needs one click and a late response cannot cross accounts', async () => {
  let finish;
  const view = app(command => command === 'wallet_enable_address' ? new Promise(resolve => { finish = resolve; }) : balance);
  await view.ui.open();
  view.ui.show('receive');
  assert.equal(view.get('wallet-address-enable').hidden, false);
  assert.equal(view.calls.filter(c => c.command === 'wallet_enable_address').length, 0);
  const pending = view.get('wallet-address-enable').onclick();
  view.get('wallet-address-enable').onclick();
  assert.equal(view.calls.filter(c => c.command === 'wallet_enable_address').length, 1);
  view.ui.sync({id: 2, label: 'Other'}, true);
  finish({...balance, lightning_address:{address:'dario@npub.cash',mint:'https://mint.example'}});
  await pending;
  assert.equal(view.get('wallet-address-value').value, '');
  assert.equal(view.get('wallet-address-box').hidden, true);
});

test('provider address displays without banners and changing it clears the old QR', async () => {
  let address = 'dario@npub.cash';
  const view = app(async () => ({...balance, lightning_address: address ? {address,mint:'https://mint.example'} : null}));
  await view.ui.open();
  assert.equal(view.get('wallet-address-enable').hidden, true);
  assert.equal(view.get('wallet-address-value').value, address);
  assert.equal(view.get('wallet-address-status').textContent, '');
  view.get('wallet-address-qr').hidden = false;
  view.get('wallet-address-qr').width = 120;
  address = null;
  await view.ui.open(true);
  assert.equal(view.get('wallet-address-enable').hidden, false);
  assert.equal(view.get('wallet-address-qr').hidden, true);
  assert.equal(view.get('wallet-address-qr').width, 0);
});

test('automatic opening does not loop after failure and Refresh still retries', async () => {
  const view = app(async () => { throw new Error('Restore this wallet in Settings.'); });
  await view.ui.open();
  await view.ui.open();
  assert.equal(view.calls.length, 1);
  assert.match(view.get('wallet-status').textContent, /Restore this wallet/);
  await view.get('wallet-refresh').onclick();
  assert.equal(view.calls.length, 2);
  view.ui.sync({ id: 2, label: 'Work' }, true);
  await view.ui.open();
  assert.equal(view.calls.length, 3);
});

test('a pasted Nostr link requires Connect and cannot pair twice while pending', async () => {
  let finish;
  const view = app(command => command === 'nwc_connections' ? [] : new Promise(resolve => { finish = resolve; }));
  view.ui.show('nostr');
  view.get('wallet-nostr-connect-uri').value = 'nostrconnect://client?secret=fixture';
  assert.equal(view.calls.filter(c => c.command !== 'nwc_connections').length, 0);
  view.get('wallet-nostr-connect-form').onsubmit({ preventDefault() {} });
  view.get('wallet-nostr-connect-form').onsubmit({ preventDefault() {} });
  assert.equal(view.calls.filter(c => c.command !== 'nwc_connections').length, 1);
  assert.equal(view.calls.find(c => c.command === 'pair_client').command, 'pair_client');
  assert.equal(view.calls.find(c => c.command === 'pair_client').args.account, 1);
  finish({});
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(view.get('wallet-nostr-connect-uri').value, '');
  assert.equal(view.get('wallet-status').textContent, '');
});

test('reimporting the same account reloads its recovered balance', async () => {
  let funds = 0;
  const view = app(async () => ({ ...balance, balance: funds }));
  await view.ui.open();
  assert.equal(view.get('wallet-balance').textContent, '0 sats');
  funds = 128;
  view.ui.sync({ id: 1, label: 'Personal' }, true);
  await view.ui.open(true);
  assert.equal(view.get('wallet-balance').textContent, '128 sats');
  await view.ui.open();
  assert.equal(view.calls.filter(call => call.command === 'wallet_open').length, 2);
});

test('loading retries an interrupted recovery automatically and then shows funds', async () => {
  let failing = true;
  const view = app(async command => {
    if (command === 'wallet_open' && failing) throw 'Fund recovery interrupted. Retrying…';
    return balance;
  });
  await view.ui.open();
  assert.equal(view.get('wallet-balance').textContent, 'Loading…');
  assert.equal(view.get('wallet-open').hidden, true);
  assert.equal(view.get('wallet-status').textContent, 'Connecting to mint…');
  await view.ui.open();
  assert.equal(view.calls.length, 1);
  failing = false;
  await view.timers.findLast(Boolean)();
  assert.equal(view.get('wallet-balance').textContent, '100 sats');
  assert.equal(view.get('wallet-status').textContent, '');
  assert.equal(view.calls.filter(call => call.command === 'wallet_open').length, 2);
});

test('locking or switching accounts cancels recovery retries', async () => {
  const view = app(async () => { throw 'Mint sync failed. Retrying…'; });
  await view.ui.open();
  const lateRetry = view.timers.findLast(Boolean);
  view.ui.sync({ id: 1, label: 'Personal' }, false);
  assert.equal(view.timers.filter(Boolean).length, 0);
  await lateRetry();
  assert.equal(view.calls.length, 1);
  view.ui.sync({ id: 1, label: 'Personal' }, true);
  await view.ui.open();
  const oldAccountRetry = view.timers.findLast(Boolean);
  view.ui.sync({ id: 2, label: 'Work' }, true);
  await oldAccountRetry();
  assert.equal(view.calls.length, 2);
});

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

test('choosing a mint clears payment approval and Minibits is the default', async () => {
  const view = app(async (command, args) => {
    if (command === 'wallet_set_mint') return { ...balance, balance: 0, mint: args.mint };
    if (command === 'wallet_review') return { quote: 'q', amount: 10, max_fee: 2, maximum: 12, expiry: 2000000000, destination: 'recipient' };
    return balance;
  });
  assert.equal(view.get('wallet-mint-url').value, 'https://mint.minibits.cash/Bitcoin');
  await view.get('wallet-open').onclick();
  view.get('wallet-pay-form').onsubmit({ preventDefault() {} });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(view.get('wallet-review').hidden, false);
  view.get('wallet-mint-url').value = 'https://mint.example';
  view.get('wallet-mint-form').onsubmit({ preventDefault() {} });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(view.get('wallet-review').hidden, true);
  assert.equal(view.get('wallet-balance').textContent, '0 sats');
  assert.equal(view.get('wallet-mint').textContent, 'Mint: https://mint.example');
  await view.get('wallet-confirm').onclick();
  assert.equal(view.calls.some(call => call.command === 'wallet_pay'), false);
  await view.get('wallet-picker').children.find(row => row.id === 'wallet-mint-default').onclick();
  assert.equal(view.calls.findLast(call => call.command === 'wallet_set_mint').args.mint, 'https://mint.minibits.cash/Bitcoin');
});

test('a late mint selection cannot overwrite another account and locked accounts cannot choose mints', async () => {
  let finish;
  const view = app(command => command === 'wallet_set_mint' ? new Promise(resolve => { finish = resolve; }) : balance);
  await view.ui.open();
  const row = view.get('wallet-picker').children.find(row => row.id === 'wallet-mint-default');
  const pending = row.onclick();
  view.ui.sync({ id: 2, label: 'Work' }, false);
  finish({ ...balance, mint: 'https://mint.example' });
  await pending;
  assert.equal(view.get('wallet-mint').textContent, '');
  assert.equal(view.get('wallet-balance').textContent, '— sats');
  await row.onclick();
  assert.equal(view.calls.filter(call => call.command === 'wallet_set_mint').length, 1);
});

test('recovery words require an explicit request and disappear on blur, timeout and account change', async () => {
  const view = app(command => command === 'wallet_backup' ? { words: 'abandon '.repeat(11) + 'about', mints: ['https://mint.example'], passphrase_required: true } : balance);
  await view.get('wallet-open').onclick();
  view.ui.show('backup');
  assert.equal(view.calls.some(call => call.command === 'wallet_backup'), false);
  await view.get('wallet-backup-show').onclick();
  assert.equal(view.get('wallet-words').children.length, 12);
  assert.equal(view.get('wallet-backup-passphrase').hidden, false);
  view.events.get('blur')();
  assert.equal(view.get('wallet-words').children.length, 0);
  await view.get('wallet-backup-show').onclick();
  view.timers.findLast(Boolean)();
  assert.equal(view.get('wallet-words').children.length, 0);
  await view.get('wallet-backup-show').onclick();
  view.ui.sync({ id: 2, label: 'Work' }, false);
  assert.equal(view.get('wallet-words').children.length, 0);
  assert.equal(view.get('wallet-backup-words').hidden, true);
});

test('leaving during a backup request prevents a late phrase reveal', async () => {
  let finish;
  const view = app(() => new Promise(resolve => { finish = resolve; }));
  view.ui.show('backup');
  const pending = view.get('wallet-backup-show').onclick();
  view.ui.show('home');
  finish({ words: 'abandon '.repeat(11) + 'about', mints: ['https://mint.example'], passphrase_required: false });
  await pending;
  assert.equal(view.get('wallet-words').children.length, 0);
  assert.equal(view.get('wallet-backup-words').hidden, true);
});


test('scanning Cashu inspects the mint but receiving still requires a click', async () => {
  const view = app(async command => command === 'wallet_inspect_token' ? { amount: 21, mint: 'https://mint.example' } : balance);
  view.ui.scan('cashuBfixture');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(view.get('wallet-token').value, 'cashuBfixture');
  assert.match(view.get('wallet-token-info').textContent, /21 sats · https:\/\/mint.example/);
  assert.equal(view.calls.some(call => call.command === 'wallet_receive'), false);
  view.get('wallet-receive-form').onsubmit({ preventDefault() {} });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(view.calls.filter(call => call.command === 'wallet_receive').length, 1);
  assert.equal(view.get('wallet-token').value, '');
});

test('Cashu sending reviews first, suppresses duplicate sends and hides tokens on blur', async () => {
  let finish;
  const view = app(async command => {
    if (command === 'wallet_review_send') return { quote: 'cashu-review', amount: 21, max_fee: 1, maximum: 22, expiry: 2000000000, destination: 'Cashu token' };
    if (command === 'wallet_send_token') return new Promise(resolve => { finish = resolve; });
    if (command === 'encode_qr') return { width: 21, modules: Array(441).fill(false) };
    return balance;
  });
  await view.ui.open();
  view.get('wallet-send-amount').value = '21';
  view.get('wallet-send-form').onsubmit({ preventDefault() {} });
  await new Promise(resolve => setImmediate(resolve));
  assert.match(view.get('wallet-confirm').textContent, /Create token/);
  assert.equal(view.calls.some(call => call.command === 'wallet_send_token'), false);
  const pending = view.get('wallet-confirm').onclick();
  await view.get('wallet-confirm').onclick();
  assert.equal(view.calls.filter(call => call.command === 'wallet_send_token').length, 1);
  finish({ wallet: balance, transfer: { id: 'operation', amount: 21, mint: 'https://mint.example', token: 'cashuBfixture' } });
  await pending;
  assert.equal(view.get('wallet-share-token').value, 'cashuBfixture');
  assert.equal(view.get('wallet-share-qr').hidden, false);
  view.events.get('blur')();
  assert.equal(view.get('wallet-share-token').value, '');
  assert.equal(view.get('wallet-share-qr').hidden, true);
});

test('a late token response never reveals bearer data after leaving the wallet', async () => {
  let finish;
  const view = app(async command => {
    if (command === 'wallet_show_token') return new Promise(resolve => { finish = resolve; });
    return { ...balance, pending_tokens: [{ id: 'operation', amount: 21 }] };
  });
  await view.ui.open();
  const pending = view.get('wallet-pending-tokens').children[1].onclick();
  view.ui.hideSecrets();
  finish({ id: 'operation', amount: 21, mint: 'https://mint.example', token: 'cashuBfixture' });
  await pending;
  assert.equal(view.get('wallet-share-token').value, '');
  assert.equal(view.calls.some(call => call.command === 'encode_qr'), false);
});

test('NWC pairing requires a click, suppresses duplicates, and hides its link on blur', async () => {
  let finish;
  const view = app(command => {
    if (command === 'nwc_connections') return [{ id: 'connection', label: 'Jumble' }];
    if (command === 'nwc_pair') return new Promise(resolve => { finish = resolve; });
    if (command === 'encode_qr') return { width: 1, modules: [true] };
    return balance;
  });
  view.ui.show('nostr');
  view.get('wallet-nwc-name').value = 'Jumble';
  assert.equal(view.calls.filter(c => c.command === 'nwc_pair').length, 0);
  view.get('wallet-nwc-form').onsubmit({ preventDefault() {} });
  view.get('wallet-nwc-form').onsubmit({ preventDefault() {} });
  assert.equal(view.calls.filter(c => c.command === 'nwc_pair').length, 1);
  finish('nostr+walletconnect://fixture?secret=test');
  await new Promise(resolve => setImmediate(resolve));
  assert.match(view.get('wallet-nwc-uri').value, /^nostr\+walletconnect:/);
  assert.equal(view.get('wallet-nwc-qr-box').hidden, false);
  view.events.get('blur')();
  assert.equal(view.get('wallet-nwc-uri').value, '');
  assert.equal(view.get('wallet-nwc-qr-box').hidden, true);
  assert.equal(view.calls.filter(c => c.command === 'wallet_pay').length, 0);
});

test('a late NWC pairing cannot reveal its secret after locking or changing accounts', async () => {
  let finish;
  const view = app(command => command === 'nwc_connections' ? [] : new Promise(resolve => { finish = resolve; }));
  view.get('wallet-nwc-name').value = 'Jumble';
  view.get('wallet-nwc-form').onsubmit({ preventDefault() {} });
  view.ui.sync({ id: 2, label: 'Other' }, false);
  finish('nostr+walletconnect://fixture?secret=test');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(view.get('wallet-nwc-uri').value, '');
  assert.equal(view.get('wallet-nwc-qr-box').hidden, true);
});

test('mints are clickable saved choices with Minibits, and refresh leaves no success banner', async () => {
  const view = app(command => command === 'wallet_list' ? { active: 'other', wallets: [
    { id: 'original', label: 'https://mint.minibits.cash/Bitcoin' },
    { id: 'other', label: 'https://mint.example' },
  ] } : balance);
  await view.ui.open();
  view.ui.show('mint');
  const rows = view.get('wallet-picker').children;
  assert.equal(rows.length, 2);
  assert.equal(rows[0].children[0].children[0].textContent, 'Minibits');
  assert.equal(rows[1].children[0].children[0].textContent, 'mint.example');
  assert.equal(rows[1]['aria-pressed'], 'true');
  await rows[0].onclick();
  assert.equal(view.calls.findLast(c => c.command === 'wallet_select').args.slot, 'original');
  assert.equal(view.get('wallet-status').textContent, '');
  view.get('wallet-mint-add').onclick();
  assert.equal(view.get('wallet-mint-form').hidden, false);
  assert.equal(view.get('wallet-mint-url').value, '');
  view.get('wallet-mint-cancel').onclick();
  assert.equal(view.get('wallet-mint-form').hidden, true);
});

test('rated mints load without selecting one and selection requires a click', async () => {
  const view = app(command => {
    if (command === 'wallet_mint_directory') return [{url:'https://rated.example',name:'Rated Mint',rating:4.9,reviews:25}];
    if (command === 'wallet_list') return {active:'original',wallets:[{id:'original',label:'https://mint.minibits.cash/Bitcoin'}]};
    return balance;
  });
  await view.ui.open();
  view.ui.show('mint');
  await new Promise(resolve => setImmediate(resolve));
  const rows = view.get('wallet-picker').children.filter(node => node.className === 'mint-row');
  assert.equal(rows.length,2);
  assert.equal(rows[1].children[0].children[0].textContent,'Rated Mint');
  assert.equal(rows[1].children[0].children[1].textContent,'4.9 / 5 · 25 reviews');
  assert.equal(view.calls.filter(c => c.command === 'wallet_set_mint').length,0);
  await rows[1].onclick();
  assert.equal(view.calls.find(c => c.command === 'wallet_set_mint').args.mint,'https://rated.example');
});

test('only an explicit refresh overrides receiving backoff and mint errors remain visible', async () => {
  const view = app(async () => ({...balance,transactions:[{direction:'Incoming',amount:100000,status:'Failed',fee:0,timestamp:1,error:'Mint rejected the collection signature.'}]}));
  await view.ui.open();
  assert.equal(view.calls.find(c=>c.command==='wallet_open').args.retryReceiving,undefined);
  assert.equal(view.get('wallet-history').children[0].children[1].children[0].textContent,'Mint rejected the collection signature.');
  await view.get('wallet-refresh').onclick();
  assert.equal(view.calls.findLast(c=>c.command==='wallet_open').args.retryReceiving,true);
});

test('name lookup and review never claim; approval uses only the native quote', async () => {
  const payment = {quote:'name-review',amount:5000,max_fee:2,maximum:5002,expiry:2000000000,destination:'dario@npub.cash · Minibits'};
  const view = app(async command => {
    if (command === 'wallet_name_status') return {};
    if (command === 'wallet_name_review') return payment;
    if (command === 'wallet_name_claim') return {wallet:balance,name:{address:'dario@npub.cash'}};
    if (command === 'wallet_list') return {wallets:[]};
    return balance;
  });
  await view.ui.open();
  await view.get('wallet-name-open').onclick();
  view.get('wallet-name-input').value='dario';
  view.get('wallet-name-form').onsubmit({preventDefault(){}});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(view.calls.filter(c=>c.command==='wallet_name_claim').length,0);
  assert.equal(view.get('wallet-confirm').textContent,'Claim name · up to 5002 sats');
  await view.get('wallet-confirm').onclick();
  const claim=view.calls.find(c=>c.command==='wallet_name_claim');
  assert.deepEqual({...claim.args},{quote:'name-review',account:1});
  assert.equal(view.get('wallet-name-address').textContent,'dario@npub.cash');
  assert.equal(view.get('wallet-name-form').hidden,true);
});

test('a pending name purchase offers retry without creating a second review', async () => {
  const pending={pending:'dario@npub.cash',can_retry:true,can_reclaim:true};
  const view=app(async command=> command==='wallet_name_status'?pending:command==='wallet_name_retry'?{wallet:balance,name:pending}:command==='wallet_list'?{wallets:[]}:balance);
  await view.ui.open();await view.get('wallet-name-open').onclick();
  assert.equal(view.get('wallet-name-form').hidden,true);
  assert.equal(view.get('wallet-name-pending').hidden,false);
  await view.get('wallet-name-retry').onclick();
  assert.equal(view.calls.filter(c=>c.command==='wallet_name_review'||c.command==='wallet_name_claim').length,0);
});

test('a late username result cannot reveal another account name', async () => {
  let finish;
  const view=app(command=>command==='wallet_name_status'?new Promise(resolve=>{finish=resolve;}):balance);
  await view.ui.open();const pending=view.get('wallet-name-open').onclick();
  view.ui.sync({id:2,label:'Other'},true);finish({address:'dario@npub.cash'});await pending;
  assert.equal(view.get('wallet-name-address').textContent,'');
  assert.equal(view.get('wallet-name-owned').hidden,true);
});
