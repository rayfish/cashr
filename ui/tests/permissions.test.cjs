const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function app(save = async () => {}) {
  class Element {
    constructor(tag) { this.tag = tag; this.children = []; this.disabled = false; }
    append(...children) { this.children.push(...children); }
    replaceChildren() { this.children = []; }
  }
  const elements = new Map();
  const get = id => {
    if (!elements.has(id)) elements.set(id, new Element('div'));
    return elements.get(id);
  };
  const clients = [1, 2].map(id => ({ id, name: `App ${id}`, public_key: 'a'.repeat(64), last_seen: 0, allow_all: false, deny_all: false, revoked: false }));
  const calls = [];
  const context = vm.createContext({
    window: { __TAURI__: { core: { invoke: async (command, args) => {
      calls.push({ command, args });
      if (command === 'clients') return clients.map(client => ({ ...client }));
      if (['set_client_allow_all', 'deny_client_actions', 'forget_client_rules'].includes(command)) {
        await save(args);
        const client = clients.find(client => client.id === args.client);
        client.allow_all = command === 'set_client_allow_all';
        client.deny_all = command === 'deny_client_actions';
      }
      return [];
    } }, event: { listen() {} } } },
    document: { getElementById: get, createElement: tag => new Element(tag) },
    setTimeout: () => 1, clearTimeout() {},
  });
  const source = fs.readFileSync(path.join(__dirname, '../main.js'), 'utf8');
  // Load the real UI functions without starting unrelated wallet polling.
  vm.runInContext(source.slice(0, source.lastIndexOf('\nwire();')), context);
  const run = code => vm.runInContext(code, context);
  run('state.account = 10; state.client = 1; state.unlockedAccounts = [10];');
  const descend = element => [element, ...element.children.flatMap(descend)];
  const buttons = () => descend(get('rule-list')).filter(child => child.tag === 'button');
  return { clients, calls, run, buttons, get };
}

test('Allow all and Forget all apply to the selected app, and forgetting works while locked', async () => {
  const view = app();
  await view.run('refreshClients();');
  await view.run('refreshRules();');
  assert.equal(view.buttons()[0].textContent, 'Allow all');
  assert.equal(view.calls.filter(call => call.command === 'set_client_allow_all').length, 0);
  await view.buttons()[0].onclick();
  assert.equal(view.clients[0].allow_all, true);
  assert.equal(view.clients[1].allow_all, false);
  assert.equal(view.buttons()[0].disabled, true);
  // Removing this permission is still possible while the account is locked.
  view.run('state.unlockedAccounts = [];');
  await view.run('refreshRules();');
  await view.buttons()[2].onclick();
  assert.equal(view.clients[0].allow_all, false);
  assert.equal(view.buttons()[0].textContent, 'Allow all');
  assert.equal(view.buttons()[0].disabled, true);
  assert.equal(view.calls.filter(call => call.command === 'forget_client_rules').length, 1);
});

test('Deny all replaces Allow all and Forget all clears the denial', async () => {
  const view = app();
  await view.run('refreshClients();');
  await view.run('refreshRules();');
  assert.deepEqual(view.buttons().map(button => button.textContent), ['Allow all', 'Deny all', 'Forget all']);
  await view.buttons()[0].onclick();
  view.run('state.unlockedAccounts = [];');
  await view.run('refreshRules();');
  await view.buttons()[1].onclick();
  assert.equal(view.clients[0].allow_all, false);
  assert.equal(view.clients[0].deny_all, true);
  assert.equal(view.clients[1].deny_all, false);
  assert.equal(view.buttons()[1].disabled, true);
  await view.buttons()[2].onclick();
  assert.equal(view.clients[0].deny_all, false);
});

test('pending approval cannot be submitted twice or switch to a different app', async () => {
  let finish;
  const view = app(() => new Promise(resolve => { finish = resolve; }));
  await view.run('refreshClients();');
  await view.run('refreshRules();');
  const button = view.buttons()[0];
  const pending = button.onclick();
  await button.onclick();
  await view.buttons()[1].onclick();
  await view.buttons()[2].onclick();
  view.run('state.client = 2;');
  await view.run('refreshRules();');
  finish();
  await pending;
  const commands = view.calls.filter(call => call.command === 'set_client_allow_all');
  assert.equal(commands.length, 1);
  assert.equal(view.calls.filter(call => ['deny_client_actions', 'forget_client_rules'].includes(call.command)).length, 0);
  assert.equal(commands[0].args.account, 10);
  assert.equal(commands[0].args.client, 1);
  assert.equal(view.clients[1].allow_all, false);
  assert.equal(view.buttons()[0].textContent, 'Allow all');
});

test('failed permission changes preserve the saved state and revoked apps cannot allow all', async () => {
  const view = app(async () => { throw new Error('Unlock this account first.'); });
  await view.run('refreshClients();');
  await view.run('refreshRules();');
  await view.buttons()[0].onclick();
  assert.equal(view.clients[0].allow_all, false);
  assert.equal(view.buttons()[0].disabled, false);
  assert.equal(view.get('toast').textContent, 'Error: Unlock this account first.');
  view.clients[0].revoked = true;
  await view.run('refreshClients();');
  await view.run('refreshRules();');
  assert.equal(view.buttons().length, 0);
});
