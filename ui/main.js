const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

const state = {
  accounts: [],
  account: null,
  clients: [],
  client: null,
  activityCursor: null,
  unlocked: false,
  unlockedAccounts: [],
  lightningAccount: null,
  lightningDirty: false,
  savingLightning: false,
  lightningLookups: new Set(),
  lightningLookupRevision: 0,
  findingLightning: false,
  needsMigration: false,
  hasKeychainCopies: false,
  hasTouchId: false,
  tab: "wallet",
  menuOpen: false,
  pending: 0,
  paymentPending: 0,
  health: [],
  pinned: false,
  busy: 0,
  savingAccount: false,
  renamingAccount: null,
  savingRename: false,
  recoverAccount: null,
  setupRevision: 0,
  scanning: false,
  preparingScan: false,
  connectingScan: false,
  scanGeneration: 0,
  scanLastTab: "wallet",
  scanLastWalletView: "home",
};

const $ = (id) => document.getElementById(id);

// --------------------------------------------------------------- the window

/// The window hides itself when it loses focus. It must not do that while an
/// approval is waiting, while the pin is down, or while a command that raises
/// a system dialog of its own is in flight: Touch ID takes the focus away, and
/// the window would vanish mid-unlock.
function syncPinned() {
  const wanted = state.pinned || state.busy > 0 || state.pending > 0 || state.paymentPending > 0;
  if (wanted === syncPinned.last) return;
  syncPinned.last = wanted;
  invoke("set_pinned", { pinned: wanted }).catch(() => {});
}

async function call(command, args, { notifyError = true } = {}) {
  state.busy += 1;
  syncPinned();
  try {
    const result = await invoke(command, args);
    return result;
  } catch (error) {
    if (notifyError) toast(String(error));
    throw error;
  } finally {
    state.busy -= 1;
    syncPinned();
  }
}

let toastTimer = null;
function toast(message) {
  const box = $("toast");
  box.textContent = message;
  box.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    box.hidden = true;
  }, 6000);
}

// -------------------------------------------------------------------- utils

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function plural(count, word) {
  return count === 1 ? word : `${word}s`;
}

function shorten(value) {
  return value.length > 20 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

function when(seconds) {
  const delta = Date.now() / 1000 - seconds;
  if (delta < 60) return "just now";
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return new Date(seconds * 1000).toLocaleDateString();
}

function relayName(url) {
  return url.replace(/^wss?:\/\//, "").replace(/\/$/, "");
}

function empty(text) {
  return el("div", "empty", text);
}

/// What a rule or a log line covers. The kind number is the truth and stays in
/// the tooltip; the name is only there so a narrow window reads as English.
function scopeLabel(method, kind, kindName) {
  if (kind === null || kind === undefined) return method;
  return `${method} · ${kindName ?? `kind ${kind}`}`;
}

function scopeTitle(method, kind) {
  return kind === null || kind === undefined
    ? method
    : `${method} · kind ${kind}`;
}

/// Copy to the clipboard, and say so on the button that asked.
async function copy(text, button) {
  const label = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
  } catch {
    button.textContent = "Select and copy";
  }
  setTimeout(() => {
    button.textContent = label;
  }, 1500);
}

/// A destructive button that needs a second click. Cheaper than a dialog, and
/// a dialog would steal the focus and put the window away.
function arm(button, label, run) {
  let armed = false;
  let timer = null;
  button.onclick = () => {
    if (armed) {
      clearTimeout(timer);
      run();
      return;
    }
    armed = true;
    button.textContent = "Sure?";
    button.classList.add("is-armed");
    timer = setTimeout(() => {
      armed = false;
      button.textContent = label;
      button.classList.remove("is-armed");
    }, 4000);
  };
}

function currentAccount() {
  return state.accounts.find((a) => a.id === state.account) ?? null;
}

// ------------------------------------------------------------------ prompts

async function refreshPrompts() {
  const prompts = await call("prompts");
  state.pending = prompts.length;
  syncPinned();

  const box = $("prompts");
  // Polling must not collapse details or reset a preview while it is being read.
  const fingerprint = JSON.stringify(prompts);
  if (refreshPrompts.last === fingerprint) return;
  refreshPrompts.last = fingerprint;
  box.replaceChildren();
  box.hidden = prompts.length === 0;
  $("pending-summary").textContent =
    state.pending + state.paymentPending === 0 ? "" : `${state.pending + state.paymentPending} waiting`;

  for (const prompt of prompts) {
    const who = prompt.client_name || "An app";
    const row = el("div", "prompt");
    row.append(
      el("div", "what", `${who} wants to ${prompt.detail}`),
      el("div", "hint", `Using ${prompt.account_label}`),
    );

    const preview = prompt.preview;
    if (preview?.explanation) row.append(el("p", "hint", preview.explanation));
    for (const field of preview?.fields ?? []) {
      const item = el("div", "request-field");
      item.append(el("span", "muted", `${field.label}: `), el("span", null, field.value));
      row.append(item);
    }
    if (preview?.content) row.append(el("blockquote", "request-preview", preview.content));
    const details = el("details", "request-details");
    details.append(
      el("summary", null, "Technical details"),
      el("div", "mono", `Method: ${prompt.method}`),
      el("div", "mono", `Client key: ${prompt.client_public_key}`),
    );
    if (prompt.kind !== null && prompt.kind !== undefined) {
      details.append(el("div", "mono", `Event kind: ${prompt.kind}${prompt.kind_name ? ` (${prompt.kind_name})` : ""}`));
    }
    row.append(details);

    const buttons = el("div", "buttons");
    const once = el("button", "primary", "Allow once");
    once.onclick = () => answer(prompt.id, true, false);
    const always = el("button", null, "Always allow");
    always.title = prompt.kind === null || prompt.kind === undefined
      ? "Allow future requests for this method from this client."
      : `Allow future kind ${prompt.kind} requests from this client, including different content or destinations.`;
    always.onclick = () => answer(prompt.id, true, true);
    const deny = el("button", "danger", "Deny");
    deny.onclick = () => answer(prompt.id, false, false);
    buttons.append(once, always, deny);

    row.append(buttons);
    box.append(row);
  }
}

async function refreshPaymentPrompts() {
  const prompts = await call('nwc_pending');
  state.paymentPending = prompts.length;
  $("pending-summary").textContent = state.pending + state.paymentPending === 0 ? "" : `${state.pending + state.paymentPending} waiting`;
  syncPinned();
  const fingerprint = JSON.stringify([prompts, state.unlockedAccounts]);
  if (refreshPaymentPrompts.last === fingerprint) return;
  refreshPaymentPrompts.last = fingerprint;
  const box = $('nwc-prompts');
  box.replaceChildren(); box.hidden = prompts.length === 0;
  for (const prompt of prompts) {
    const row = el('div', 'prompt payment-prompt');
    row.append(el('div', 'what', `${prompt.app} · ${prompt.account_label}`),
      el('strong', 'payment-amount', `${prompt.amount.toLocaleString()} sats`),
      el('div', 'hint', `Max fee ${prompt.max_fee} sats · Total up to ${prompt.maximum} sats`),
      el('div', 'hint', prompt.mint),
      el('div', 'hint', `Payee ${prompt.destination.slice(0, 12)}…${prompt.destination.slice(-8)}`));
    const buttons = el('div', 'buttons');
    const approve = el('button', 'primary', 'Approve & pay');
    approve.disabled = !state.unlockedAccounts.includes(prompt.account);
    const reject = el('button', null, 'Decline');
    const status = el('p', 'hint');
    let answering = false;
    const answer = async allow => {
      if (answering) return;
      answering = true;
      approve.disabled = reject.disabled = true;
      try {
        await call('nwc_answer', { id: prompt.id, allow }, { notifyError: false });
        await refreshPaymentPrompts();
      } catch (error) {
        answering = false;
        status.textContent = String(error);
        approve.disabled = !state.unlockedAccounts.includes(prompt.account); reject.disabled = false;
      }
    };
    approve.onclick = () => answer(true); reject.onclick = () => answer(false);
    buttons.append(approve, reject); row.append(buttons, status); box.append(row);
  }
}

async function answer(id, allow, remember) {
  await call("answer_prompt", { id, allow, remember });
  await refreshPrompts();
  if (remember) await refreshRules();
}

// ----------------------------------------------------------------- accounts

async function refreshStatus() {
  const status = await call("status");
  state.unlocked = status.unlocked;
  state.unlockedAccounts = status.unlocked_accounts ?? [];
  state.accounts = status.accounts;
  state.needsMigration = status.needs_migration;
  state.hasKeychainCopies = status.has_keychain_copies;
  state.hasTouchId = status.has_touch_id;
  if (!currentAccount()) {
    state.account =
      state.accounts.find((a) => a.is_default)?.id ??
      state.accounts[0]?.id ??
      null;
  }

  const selectedUnlocked = currentAccount() ? state.unlockedAccounts.includes(state.account) : state.unlocked;
  $("lock-dot").className = `dot ${selectedUnlocked ? "is-up" : "is-down"}`;
  $("lock-dot").title = selectedUnlocked ? "Account unlocked" : "Account locked";
  const toggle = $("lock-toggle");
  toggle.textContent = selectedUnlocked ? "Lock" : "Unlock";
  toggle.title = selectedUnlocked
    ? "Lock all accounts"
    : "Unlock wallet";

  renderUnlock();
  renderAccountPicker();
  renderAccountCard();
  renderAccountList();
  renderLightningAddress();
  window.WalletUI?.sync(currentAccount(), state.unlockedAccounts.includes(state.account));
  if (state.tab === "wallet") window.WalletUI?.open();
  renderRelays();
}

function renderUnlock() {
  const selectedUnlocked = state.unlockedAccounts.includes(state.account);
  $("unlock").hidden = !currentAccount() || selectedUnlocked || state.tab === "setup";
  $("unlock-title").textContent = state.hasTouchId ? "Unlock" : "Recover wallet";
  $("unlock-touch-id").hidden = !state.hasTouchId;
  $("keychain-leftover").hidden = !(state.unlocked && state.hasKeychainCopies);
  syncAccountForm();
}

async function unlockWithTouchId() {
  const button = $("unlock-touch-id");
  const error = $("unlock-error");
  const label = button.textContent;
  button.disabled = true;
  button.textContent = "Working…";
  error.hidden = true;

  // The Touch ID sheet takes the focus, which would send an unpinned window
  // away in the middle of the unlock.
  state.busy += 1;
  syncPinned();
  try {
    await invoke("unlock_with_touch_id", { account: state.account });
    await refreshAll();
  } catch (failure) {
    await refreshStatus();
    error.textContent = String(failure);
    error.hidden = false;
  } finally {
    state.busy -= 1;
    syncPinned();
    button.disabled = false;
    button.textContent = label;
  }
}

function renderAccountPicker() {
  const picker = $("account-picker");
  picker.replaceChildren();
  if (state.accounts.length === 0) {
    picker.append(el("option", null, "No account"));
    picker.disabled = true;
    return;
  }
  picker.disabled = false;
  for (const account of state.accounts) {
    const option = el("option", null, account.label);
    option.value = String(account.id);
    picker.append(option);
  }
  picker.value = String(state.account);
}

function renderAccountCard() {
  const card = $("account-card");
  card.replaceChildren();
  const account = currentAccount();

  card.className = "card stack account-overview";
  if (!account) {
    const add = el("button", "primary start", "Create wallet");
    add.onclick = () => startWalletSetup(false);
    card.append(
      el("div", "title", "Add your first account"),
      add,
    );
    return;
  }

  const head = el("div", "card-head");
  const avatar = el("span", "identity-avatar", account.label.trim().slice(0, 1).toUpperCase() || "B");
  avatar.setAttribute("aria-hidden", "true");
  head.append(
    avatar,
    el("span", "grow title", account.label),
    el(
      "span",
      `pill ${state.unlockedAccounts.includes(account.id) ? "is-allow" : ""}`,
      state.unlockedAccounts.includes(account.id) ? "Unlocked" : "Locked",
    ),
  );

  const key = el("div", "mono", account.npub);
  key.title = account.npub;

  const copyKey = el("button", "ghost start", "Copy npub");
  copyKey.onclick = () => copy(account.npub, copyKey);

  const identityKey = el("div", "identity-key");
  identityKey.append(key, copyKey);
  card.append(el("span", "eyebrow", "Nostr identity"), head, identityKey);
}

function renderLightningAddress() {
  const account = currentAccount();
  const changedAccount = state.lightningAccount !== (account?.id ?? null);
  if (changedAccount) {
    state.lightningLookupRevision++;
    state.findingLightning = false;
    state.lightningAccount = account?.id ?? null;
    state.lightningDirty = false;
    $("lightning-status").textContent = "";
  }
  if (changedAccount || !state.lightningDirty) {
    $("lightning-address").value = account?.lightning_address ?? "";
  }
  $("lightning-address").disabled = !account || state.savingLightning;
  $("lightning-save").disabled = !account || state.savingLightning;
  $("lightning-remove").disabled = state.savingLightning;
  $("lightning-remove").hidden = !account?.lightning_address;
  $('lightning-find').disabled = !account || state.findingLightning || state.savingLightning || !!$('lightning-address').value.trim();
  $('lightning-find').textContent = state.findingLightning ? 'Finding…' : 'Find address';
  if (state.tab === 'settings' && account && !account.lightning_address && !state.lightningDirty && !state.lightningLookups.has(account.id)) findLightningAddress();
}

async function findLightningAddress() {
  const account = currentAccount();
  if (!account || state.findingLightning || $('lightning-address').value.trim()) return;
  state.lightningLookups.add(account.id);
  const revision = ++state.lightningLookupRevision;
  state.findingLightning = true;
  renderLightningAddress();
  try {
    const address = await call('find_lightning_address', { account: account.id }, { notifyError: false });
    if (revision !== state.lightningLookupRevision || state.account !== account.id) return;
    if (address) {
      $('lightning-address').value = address;
      state.lightningDirty = true;
    }
    $('lightning-status').textContent = address ? '' : 'No address found.';
  } catch (error) {
    if (revision === state.lightningLookupRevision) $('lightning-status').textContent = String(error);
  } finally {
    if (revision === state.lightningLookupRevision) {
      state.findingLightning = false;
      renderLightningAddress();
    }
  }
}

async function saveLightningAddress(remove = false) {
  const account = currentAccount();
  if (!account || state.savingLightning) return;
  state.lightningLookupRevision++;
  state.findingLightning = false;
  state.lightningLookups.add(account.id);
  const address = remove ? null : $("lightning-address").value.trim();
  if (!remove && !address) {
    $("lightning-status").textContent = "Enter a Lightning address.";
    $("lightning-address").focus();
    return;
  }
  state.savingLightning = true;
  // Keep an unsaved value intact while status refreshes are in flight.
  state.lightningDirty = true;
  renderLightningAddress();
  try {
    await call("set_lightning_address", { account: account.id, address });
    if (state.account === account.id) state.lightningDirty = false;
    await refreshStatus();
    if (state.account === account.id) $("lightning-status").textContent = '';
  } catch {
    if (state.account === account.id) $("lightning-status").textContent = "Could not save. Check the address.";
  } finally {
    state.savingLightning = false;
    renderLightningAddress();
  }
}

function renderAccountList() {
  if (state.renamingAccount !== null && !state.accounts.some(account => account.id === state.renamingAccount)) closeRename();
  const list = $("account-list");
  list.replaceChildren();
  if (state.accounts.length === 0) {
    list.append(empty("No accounts yet."));
    return;
  }

  for (const account of state.accounts) {
    const card = el("div", "card account-card");
    const details = el("div", "account-card-details");
    details.append(el("div", "title", account.label), el("div", "mono", account.npub));
    const badges = el("div", "account-card-badges");
    badges.append(el("span", `pill ${state.unlockedAccounts.includes(account.id) ? "is-allow" : ""}`, state.unlockedAccounts.includes(account.id) ? "Unlocked" : "Locked"));
    card.append(details, badges);
    const actions = el("div", "account-card-actions");

    if (account.is_default) {
      badges.append(el("span", "pill", "default"));
    } else {
      const makeDefault = el("button", "account-card-default", "Make default");
      makeDefault.onclick = async () => {
        await call("set_default_account", { account: account.id });
        await refreshStatus();
      };
      actions.append(makeDefault);
    }

    const rename = el("button", null, "Rename");
    rename.disabled = state.savingRename;
    rename.onclick = () => {
      state.renamingAccount = account.id;
      $('account-rename-label').value = account.label;
      $('account-rename-error').textContent = '';
      $('account-rename').hidden = false;
      $('account-rename-label').focus();
      $('account-rename-label').select();
    };
    actions.append(rename);

    const remove = el("button", "danger", "Delete");
    arm(remove, "Delete", async () => {
      await call("delete_account", { account: account.id });
      await refreshAll();
    });
    actions.append(remove);
    card.append(actions);

    list.append(card);
  }
}

function closeRename() {
  state.renamingAccount = null;
  $('account-rename').hidden = true;
  $('account-rename-label').value = '';
  $('account-rename-error').textContent = '';
}

async function saveRename(event) {
  event.preventDefault();
  if (state.savingRename || state.renamingAccount === null) return;
  const label = $('account-rename-label').value.trim();
  if (!label) {
    $('account-rename-error').textContent = 'Enter a wallet name.';
    return;
  }
  state.savingRename = true;
  for (const id of ['account-rename-label', 'account-rename-save', 'account-rename-cancel']) $(id).disabled = true;
  renderAccountList();
  try {
    await call('rename_account', { account: state.renamingAccount, label }, { notifyError: false });
    closeRename();
    await refreshStatus();
  } catch (error) {
    $('account-rename-error').textContent = String(error);
  } finally {
    state.savingRename = false;
    for (const id of ['account-rename-label', 'account-rename-save', 'account-rename-cancel']) $(id).disabled = false;
    renderAccountList();
  }
}

// -------------------------------------------------------------------- relays

function renderRelays() {
  const list = $("relay-list");
  list.replaceChildren();
  const account = currentAccount();
  if (!account) return;
  if (account.relays.length === 0) {
    list.append(empty("No relays connected."));
    renderRelayHealth();
    return;
  }

  for (const url of account.relays) {
    const card = el("div", "card");
    const dot = el("span", "dot");
    dot.dataset.url = url;
    const name = el("span", "grow", relayName(url));
    name.title = url;

    const remove = el("button", "danger", "Remove");
    arm(remove, "Remove", async () => {
      const relays = account.relays.filter((r) => r !== url);
      await call("set_relays", { account: account.id, relays });
      await refreshStatus();
    });

    card.append(dot, name, remove);
    list.append(card);
  }
  renderRelayHealth();
}

function renderRelayHealth() {
  const account = currentAccount();
  const total = account?.relays.length ?? 0;
  let up = 0;

  for (const dot of document.querySelectorAll("#relay-list .dot")) {
    const entry = state.health.find((h) => h.url === dot.dataset.url);
    const connected = Boolean(entry?.connected);
    if (connected) up += 1;
    dot.className = `dot ${connected ? "is-up" : "is-down"}`;
    dot.title = connected ? "connected" : (entry?.last_error ?? "not connected");
  }

  $("relay-summary").textContent =
    total === 0 ? "No relays configured" : `${up} of ${total} relays connected`;
  $("connection-dot").className = `dot ${up > 0 ? "is-up" : ""}`;
}

async function refreshRelayHealth() {
  if (state.account === null) return;
  state.health = await call("relay_health", { account: state.account });
  renderRelayHealth();
}

// ------------------------------------------------------------------ clients

async function refreshClients() {
  state.clients =
    state.account === null ? [] : await call("clients", { account: state.account });

  const list = $("client-list");
  list.replaceChildren();
  if (state.clients.length === 0) {
    list.append(empty("No Nostr apps connected."));
  }

  for (const client of state.clients) {
    const card = el("div", "card");
    const grow = el("div", "grow");
    grow.append(
      el("div", null, client.name ?? "Unnamed client"),
      el(
        "div",
        "mono",
        `${shorten(client.public_key)} · seen ${when(client.last_seen)}`,
      ),
    );
    card.append(grow);

    if (client.revoked) {
      card.append(el("span", "pill is-deny", "revoked"));
    } else {
      const rules = el("button", null, "Rules");
      rules.onclick = async () => {
        state.client = client.id;
        selectTab("rules");
        await refreshRules();
      };

      const revoke = el("button", "danger", "Revoke");
      arm(revoke, "Revoke", async () => {
        await call("revoke_client", { client: client.id });
        await refreshClients();
        await refreshRules();
      });

      card.append(rules, revoke);
    }

    // Offered on every row, revoked ones included: a revoked client otherwise
    // has no action at all and sits in the list forever. Removing revokes on
    // the way out, so it is never the softer choice of the two.
    const remove = el("button", "danger", "Remove");
    arm(remove, "Remove", async () => {
      await call("remove_client", { client: client.id });
      await refreshClients();
      await refreshRules();
    });
    card.append(remove);

    list.append(card);
  }

  const picker = $("rule-client");
  picker.replaceChildren();
  for (const client of state.clients) {
    const option = el("option", null, client.name ?? shorten(client.public_key));
    option.value = String(client.id);
    picker.append(option);
  }
  if (!state.clients.some((c) => c.id === state.client)) {
    state.client = state.clients[0]?.id ?? null;
  }
  picker.disabled = state.clients.length === 0;
  if (state.client !== null) picker.value = String(state.client);
}

// -------------------------------------------------------------------- rules

async function refreshRules() {
  const list = $("rule-list");
  list.replaceChildren();
  if (state.client === null) {
    list.append(empty("No Nostr apps connected."));
    return;
  }

  const rules = await call("rules", { client: state.client });
  if (rules.length === 0) {
    list.append(empty("Ask for every request."));
    return;
  }

  for (const rule of rules) {
    const card = el("div", "card");
    const what = el("span", "grow", rule.description || scopeLabel(rule.method, rule.kind, rule.kind_name));
    what.title = scopeTitle(rule.method, rule.kind);
    card.append(
      what,
      el("span", `pill ${rule.allow ? "is-allow" : "is-deny"}`, rule.allow ? "allow" : "deny"),
    );

    const flip = el("button", null, rule.allow ? "Deny" : "Allow");
    flip.onclick = async () => {
      await call("set_rule", {
        client: state.client,
        method: rule.method,
        kind: rule.kind,
        allow: !rule.allow,
      });
      await refreshRules();
    };

    const clear = el("button", "danger", "Forget");
    clear.onclick = async () => {
      await call("clear_rule", {
        client: state.client,
        method: rule.method,
        kind: rule.kind,
      });
      await refreshRules();
    };

    card.append(flip, clear);
    list.append(card);
  }
}

// ----------------------------------------------------------------- activity

const OUTCOME_PILL = {
  allowed: "is-allow",
  denied: "is-deny",
  deferred: "is-warn",
  failed: "is-deny",
};

async function refreshActivity(append = false) {
  const list = $("activity-list");
  if (!append) {
    state.activityCursor = null;
    list.replaceChildren();
  }
  if (state.account === null) {
    list.append(empty("No account selected."));
    $("activity-more").hidden = true;
    return;
  }

  const entries = await call("activity", {
    account: state.account,
    limit: 25,
    before: state.activityCursor,
  });

  if (!append && entries.length === 0) {
    list.append(empty("No activity yet."));
  }

  for (const entry of entries) {
    const card = el("div", "card");
    const grow = el("div", "grow");
    const what = el("div", null, entry.description || scopeLabel(entry.method, entry.kind, entry.kind_name));
    what.title = scopeTitle(entry.method, entry.kind);
    grow.append(what, el("div", "mono", `${when(entry.at)} · ${entry.source}`));
    card.append(
      grow,
      el("span", `pill ${OUTCOME_PILL[entry.outcome] ?? ""}`, entry.outcome),
    );
    list.append(card);
  }

  state.activityCursor = entries.at(-1)?.id ?? state.activityCursor;
  $("activity-more").hidden = entries.length < 25;
}

// ------------------------------------------------------------------- wiring

function recoveryFields(count = Number($('recovery-count').value) || 12) {
  return Array.from({ length: count }, (_, index) => $('recovery-word-' + (index + 1)));
}

function setRecoveryCount(count) {
  $('recovery-count').value = String(count);
  for (let index = 1; index <= 24; index++) {
    $('recovery-slot-' + index).hidden = index > count;
    if (index > count) $('recovery-word-' + index).value = '';
  }
}

function setRecoveryVisible(visible) {
  for (const field of recoveryFields(24)) field.type = visible ? 'text' : 'password';
  $('recovery-visibility').textContent = visible ? 'Hide words' : 'Show words';
  $('recovery-visibility').setAttribute('aria-pressed', String(visible));
}

function clearRecoveryWords() {
  setRecoveryVisible(false);
  for (const field of recoveryFields(24)) field.value = '';
  setRecoveryCount(12);
  $('account-error').textContent = '';
}

function pasteRecoveryWords(event, index) {
  if (state.savingAccount) return;
  event.preventDefault();
  const words = event.clipboardData.getData('text').trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return;
  const wholePhrase = words.length === 12 || words.length === 24;
  const start = wholePhrase ? 0 : index;
  if (!wholePhrase && words.length > recoveryFields().length - start) {
    $('account-error').textContent = 'Paste a complete 12- or 24-word phrase.';
    return;
  }
  if (wholePhrase) setRecoveryCount(words.length);
  const fields = recoveryFields();
  words.forEach((word, offset) => { fields[start + offset].value = word; });
  $('account-error').textContent = '';
  fields[Math.min(start + words.length, fields.length - 1)].focus();
}

function syncAccountForm() {
  const busy = state.savingAccount;
  $("account-create").disabled = busy;
  $("account-import").disabled = busy;
  $("account-label").disabled = busy;
  for (const id of ["recovery-count", "recovery-visibility", "account-mint", "account-recovery-passphrase"]) $(id).disabled = busy;
  for (const field of recoveryFields(24)) field.disabled = busy;
  $("account-cancel").disabled = busy;
  $("account-add").disabled = busy;
}

function showAccountForm(shown) {
  $("account-new").hidden = !shown;
  $("account-add").setAttribute("aria-expanded", String(shown));
  if (shown) {
    $("account-label").focus();
  } else {
    state.setupRevision++;
    state.recoverAccount = null;
    $("account-label").value = "";
    clearRecoveryWords();
    $("account-recovery-passphrase").value = "";
    $("account-mint").value = "https://mint.minibits.cash/Bitcoin";
  }
}

function startWalletSetup(importing, recoverAccount = null) {
  state.setupRevision++;
  selectTab('setup');
  $('setup-heading').textContent = importing ? 'Import wallet' : 'Create wallet';
  $('account-create').hidden = importing;
  $('account-import-fields').hidden = !importing;
  showAccountForm(true);
  state.recoverAccount = recoverAccount;
  $('account-reconnect-hint').hidden = !recoverAccount || !state.clients?.length;
  syncAccountForm();
  $(importing ? 'recovery-word-1' : 'account-label').focus();
}

async function saveAccount(importing) {
  if (state.savingAccount) return;
  const fields = recoveryFields();
  if (importing) {
    const missing = fields.find(field => !field.value.trim());
    if (missing) {
      $('account-error').textContent = 'Enter all recovery words.';
      missing.focus();
      return;
    }
  }
  const revision = state.setupRevision;
  const label = $("account-label").value.trim() || (importing ? "Restored" : "Wallet");
  const recovery = importing ? { account: state.recoverAccount, mnemonic: fields.map(field => field.value.trim().toLowerCase()).join(' '), passphrase: $("account-recovery-passphrase").value, mint: $("account-mint").value } : null;
  const button = $(importing ? "account-import" : "account-create");
  const originalLabel = button.textContent;
  state.savingAccount = true;
  button.textContent = importing ? "Restoring…" : "Creating…";
  syncAccountForm();
  try {
    clearRecoveryWords();
    $("account-recovery-passphrase").value = "";
    const account = await call(importing ? "import_account" : "create_account", importing ? { label, recovery } : { label }, { notifyError: false });
    state.account = account.id;
    showAccountForm(false);
    await refreshAll();
    selectTab("wallet", true);
    if (!importing) {
      window.WalletUI?.show("backup");
      $("wallet-status").textContent = "Back up your recovery words.";
    }
  } catch (error) {
    if (state.tab === 'setup' && revision === state.setupRevision) {
      $('account-error').textContent = String(error);
      if (recovery && ['Authentication cancelled.', 'Authentication was interrupted. Try again.', 'Authentication failed. Try again.', 'macOS authentication is unavailable. Try again.'].includes(String(error))) {
        const words = recovery.mnemonic.split(' ');
        setRecoveryCount(words.length);
        recoveryFields().forEach((field, index) => { field.value = words[index]; });
        $('account-recovery-passphrase').value = recovery.passphrase;
      }
    }
  } finally {
    if (recovery) { recovery.mnemonic = ""; recovery.passphrase = ""; }
    state.savingAccount = false;
    button.textContent = originalLabel;
    syncAccountForm();
    if (state.tab === "settings" && $("account-new").hidden) $("account-add").focus();
  }
}

function clearScan() {
  state.scanGeneration += 1;
  $("scan-results").replaceChildren();
  $("scan-status").textContent = "";
  $("scan-input").hidden = false;
}

async function prepareScanner() {
  if (state.preparingScan) return;
  state.preparingScan = true;
  let screenAllowed = false;
  const generation = state.scanGeneration;
  $("scan-screen").disabled = true;
  $("scan-clipboard").disabled = true;
  try {
    // Give the scanner panel a frame to appear before macOS opens its prompt.
    await new Promise((resolve) => requestAnimationFrame(resolve));
    if (state.tab !== "scan" || state.scanGeneration !== generation) return;
    const allowed = await call("prepare_scan");
    screenAllowed = allowed;
    if (state.tab !== "scan" || state.scanGeneration !== generation) return;
    $("scan-status").textContent = allowed ? ""
      : "Allow Screen Recording in System Settings, or paste an image.";
  } catch (error) {
    if (state.tab === "scan" && state.scanGeneration === generation) $("scan-status").textContent = String(error);
  } finally {
    state.preparingScan = false;
    $("scan-screen").disabled = false;
    $("scan-clipboard").disabled = false;
    if (state.tab === "scan" && state.scanGeneration === generation) {
      $(screenAllowed ? "scan-screen" : "scan-clipboard").focus();
    }
  }
}

function toggleScanner(walletView = "home") {
  if (state.tab === "scan") {
    if (state.scanning || state.connectingScan) return;
    selectTab(state.scanLastTab);
    if (state.scanLastTab === "wallet") {
      window.WalletUI?.show(state.scanLastWalletView);
      $("wallet-show-nostr").focus();
    }
  } else {
    state.scanLastTab = state.tab;
    state.scanLastWalletView = typeof walletView === "string" ? walletView : "home";
    selectTab("scan");
    $("scan-screen").focus();
    prepareScanner();
  }
}

async function connectScannedClient(uri, button) {
  if (state.connectingScan) return;
  if (state.account === null) return toast("Add an account in Settings first.");
  if (!state.unlocked) return toast("Unlock Cashr above before connecting.");
  state.connectingScan = true;
  button.disabled = true;
  button.textContent = "Connecting…";
  try {
    const paired = await call("pair_client", { account: state.account, uri });
    clearScan();
    selectTab("clients");
    toast(`Connected ${paired.client_name || shorten(paired.client_public_key)}.`);
    await refreshAll();
  } catch {
    // The command reports failures; retain the result so the user can retry.
  } finally {
    state.connectingScan = false;
    button.disabled = false;
    button.textContent = "Connect";
  }
}

function renderScannedCodes(codes) {
  const list = $("scan-results");
  list.replaceChildren();
  $("scan-input").hidden = codes.length > 0;
  for (const raw of codes) {
    const result = CashrQR.describe(raw);
    const card = el("div", "card stack");
    const title = el("h2", "scan-result-title", result.title);
    const hint = el("p", "hint", result.hint);
    if (result.action === "pair") {
      const connect = el("button", "primary", "Connect");
      connect.onclick = () => connectScannedClient(result.value, connect);
      card.append(title, hint, connect);
      list.append(card);
      if (list.children.length === 1) connect.focus();
      continue;
    }
    if (window.WalletUI && ["receive", "pay"].includes(result.action)) {
      const review = el("button", "primary", result.action === "receive" ? "Review token" : "Review payment");
      review.onclick = () => {
        clearScan();
        selectTab("wallet");
        window.WalletUI.scan(raw.trim());
      };
      card.append(title, hint, review);
      list.append(card);
      continue;
    }
    const content = el("textarea", "scan-content mono");
    content.readOnly = true;
    content.spellcheck = false;
    content.setAttribute("aria-label", `${result.title} content`);
    content.hidden = true;
    const actions = el("div", "row");
    const reveal = el("button", "ghost", "Show content");
    reveal.setAttribute("aria-expanded", "false");
    reveal.onclick = () => {
      content.hidden = !content.hidden;
      content.value = content.hidden ? "" : raw;
      reveal.textContent = content.hidden ? "Show content" : "Hide content";
      reveal.setAttribute("aria-expanded", String(!content.hidden));
    };
    const copyButton = el("button", "ghost", "Copy");
    copyButton.onclick = () => copy(raw, copyButton);
    actions.append(reveal, copyButton);
    card.append(title, hint, content, actions);
    list.append(card);
    if (list.children.length === 1) reveal.focus();
  }
}

async function scanQR(source) {
  if (state.scanning || state.preparingScan || state.connectingScan) return;
  clearScan();
  const generation = state.scanGeneration;
  state.scanning = true;
  for (const id of ["scan-screen", "scan-clipboard"]) $(id).disabled = true;
  $("scan-status").textContent = source === "screen"
    ? "Select an area around the QR code. Press Esc to cancel."
    : "Reading the clipboard image…";
  try {
    const codes = await call(source === "screen" ? "scan_screen" : "scan_clipboard");
    if (state.tab !== "scan" || state.scanGeneration !== generation) return;
    if (codes === null) {
      $("scan-status").textContent = "Scan cancelled.";
    } else {
      renderScannedCodes(codes);
      $("scan-status").textContent = codes.length === 1 ? "" : `${codes.length} QR codes found. Choose one below.`;
    }
  } catch (error) {
    if (state.tab === "scan" && state.scanGeneration === generation) {
      $("scan-status").textContent = String(error);
    }
  } finally {
    state.scanning = false;
    for (const id of ["scan-screen", "scan-clipboard"]) $(id).disabled = false;
    if (state.tab === "scan" && !$("scan-input").hidden) $(source === "screen" ? "scan-screen" : "scan-clipboard").focus();
  }
}

function closeMenu(restoreFocus = false) {
  state.menuOpen = false;
  $("main-menu").hidden = true;
  $("menu-dismiss").hidden = true;
  $("menu-toggle").setAttribute("aria-expanded", "false");
  if (restoreFocus) $("menu-toggle").focus();
}

function toggleMenu() {
  if (state.menuOpen) return closeMenu(true);
  state.menuOpen = true;
  $("main-menu").hidden = false;
  $("menu-dismiss").hidden = false;
  $("menu-toggle").setAttribute("aria-expanded", "true");
  $("nav-wallet").focus();
}

function selectTab(name, refreshWallet = false) {
  closeMenu();
  window.WalletUI?.hideSecrets?.();
  if (state.tab === "scan" && name !== "scan") clearScan();
  if (state.tab === "setup" && name !== "setup") showAccountForm(false);
  state.tab = name;
  for (const tab of document.querySelectorAll("[data-tab]")) {
    const selected = tab.dataset.tab === name;
    tab.classList.toggle("is-active", selected);
    tab.setAttribute("aria-current", selected ? "page" : "false");
  }
  for (const panel of document.querySelectorAll(".panel")) {
    panel.classList.toggle("is-active", panel.id === `tab-${name}`);
  }
  $("settings-toggle").setAttribute("aria-pressed", String(name === "settings"));
  $("scroll").scrollTop = 0;
  $("page-back").hidden = name === "wallet";
  renderUnlock();
  if (name === "wallet") {
    window.WalletUI?.show("home");
    window.WalletUI?.open(refreshWallet);
  }
  if (name === 'settings') renderLightningAddress();
}

async function refreshAll() {
  await refreshStatus();
  await refreshClients();
  await refreshRules();
  await refreshActivity();
  await refreshPrompts();
  await refreshPaymentPrompts();
  await refreshRelayHealth();
}

function wire() {
  $('account-rename').onsubmit = saveRename;
  $('account-rename-cancel').onclick = closeRename;
  $('recovery-visibility').onclick = () => setRecoveryVisible($('recovery-visibility').getAttribute('aria-pressed') !== 'true');
  window.addEventListener('blur', () => setRecoveryVisible(false));
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) setRecoveryVisible(false);
  });
  $('recovery-count').onchange = () => setRecoveryCount(Number($('recovery-count').value));
  recoveryFields(24).forEach((field, index) => {
    field.onpaste = event => pasteRecoveryWords(event, index);
    field.onkeydown = event => {
      if (event.key === ' ' && field.value.trim()) {
        event.preventDefault();
        recoveryFields()[Math.min(index + 1, recoveryFields().length - 1)].focus();
      }
    };
    field.oninput = () => { $('account-error').textContent = ''; };
  });
  window.WalletUI?.init((command, args) => call(command, args, { notifyError: false }));
  $("lightning-form").onsubmit = (event) => {
    event.preventDefault();
    saveLightningAddress();
  };
  $("lightning-address").oninput = () => {
    state.lightningLookupRevision++;
    state.findingLightning = false;
    state.lightningDirty = true;
    $("lightning-status").textContent = "";
    renderLightningAddress();
  };
  $('lightning-find').onclick = findLightningAddress;
  $("lightning-remove").onclick = () => saveLightningAddress(true);
  for (const view of ["receive", "send", "nostr"]) $("wallet-scan-" + view).onclick = () => toggleScanner(view);
  $("scan-screen").onclick = () => scanQR("screen");
  $("scan-clipboard").onclick = () => scanQR("clipboard");
  document.addEventListener("paste", (event) => {
    if (state.tab !== "scan" || event.target?.matches("input, textarea")) return;
    event.preventDefault();
    scanQR("clipboard");
  });
  $("menu-toggle").onclick = toggleMenu;
  $("menu-dismiss").onclick = () => closeMenu(true);
  $("page-back").onclick = () => selectTab("wallet");
  for (const tab of document.querySelectorAll("[data-tab]")) {
    tab.onclick = () => selectTab(tab.dataset.tab);
  }
  const menuButtons = [$("nav-wallet"), $("nav-home"), $("nav-clients"), $("settings-toggle")];
  for (const [index, button] of menuButtons.entries()) {
    button.onkeydown = event => {
      const next = { ArrowRight: (index + 1) % 4, ArrowLeft: (index + 3) % 4, ArrowDown: (index + 2) % 4, ArrowUp: (index + 2) % 4, Home: 0, End: 3 }[event.key];
      if (next === undefined) return;
      event.preventDefault();
      menuButtons[next].focus();
    };
  }
  document.addEventListener("focusin", event => {
    if (state.menuOpen && !$("main-menu").contains(event.target) && event.target !== $("menu-toggle")) closeMenu();
  });
  for (const view of ["mint", "backup"]) {
    $("settings-" + view).onclick = () => {
      selectTab("wallet");
      window.WalletUI?.show(view);
    };
  }

  $("settings-import").onclick = () => startWalletSetup(true);
  $("wallet-create").onclick = () => startWalletSetup(false);
  $("wallet-import").onclick = () => startWalletSetup(true);

  $("account-picker").onchange = async (event) => {
    state.account = Number(event.target.value);
    await refreshAll();
  };

  $("lock-toggle").onclick = async () => {
    if (currentAccount() ? state.unlockedAccounts.includes(state.account) : state.unlocked) {
      await call("lock");
      await refreshAll();
      return;
    }
    // Touch ID is one press, so send the user there rather than to a field
    // they would have to type in.
    if (state.hasTouchId) {
      unlockWithTouchId();
      return;
    }
    startWalletSetup(true, state.account);
  };

  $("unlock-touch-id").onclick = () => unlockWithTouchId();

  $("unlock-recover").onclick = () => startWalletSetup(true, state.account);

  arm($("forget-keychain"), "Delete the Keychain copies", async () => {
    await call("forget_keychain");
    await refreshAll();
  });

  const pin = $("pin-toggle");
  pin.onclick = () => {
    state.pinned = !state.pinned;
    pin.setAttribute("aria-pressed", String(state.pinned));
    syncPinned();
  };

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && state.menuOpen) {
      event.preventDefault();
      closeMenu(true);
      return;
    }
    if (event.key === "Escape" && state.tab === "scan") {
      event.preventDefault();
      toggleScanner();
      return;
    }
    if (event.key === "Escape" && !state.pinned) {
      window.WalletUI?.hideSecrets?.();
      invoke("hide_window").catch(() => {});
    }
  });

  $("account-add").onclick = () => startWalletSetup(false);
  $("account-cancel").onclick = () => {
    showAccountForm(false);
    selectTab('wallet');
  };
  $("account-create").onclick = () => saveAccount(false);
  $("account-import").onclick = () => saveAccount(true);

  $("relay-add").onclick = async () => {
    const account = currentAccount();
    const url = $("relay-url").value.trim();
    if (!account || !url) return;
    await call("set_relays", {
      account: account.id,
      relays: [...account.relays, url],
    });
    $("relay-url").value = "";
    await refreshStatus();
  };

  $("pair-bunker").onclick = async (event) => {
    if (state.account === null) return toast("Add an account first.");
    const uri = await call("pair_bunker", { account: state.account });
    const output = $("pair-output");
    output.textContent = uri;
    output.hidden = false;
    await copy(uri, event.currentTarget);
  };

  $("pair-paste").onclick = () => {
    const form = $("pair-form");
    form.hidden = !form.hidden;
    if (!form.hidden) $("pair-uri").focus();
  };

  const pair = async () => {
    const uri = $("pair-uri").value.trim();
    if (state.account === null) return toast("Add an account first.");
    if (!uri) return toast("Paste the nostrconnect:// URI first.");

    const paired = await call("pair_client", { account: state.account, uri });
    $("pair-uri").value = "";
    $("pair-form").hidden = true;

    const who = paired.client_name || shorten(paired.client_public_key);
    const count = paired.added_relays.length;
    const relays =
      count === 0 ? "" : ` Listening on ${count} more ${plural(count, "relay")}.`;
    const output = $("pair-output");
    output.textContent = `Paired with ${who}.${relays}`;
    output.hidden = false;
    await refreshAll();
  };

  $("pair-client").onclick = pair;
  $("pair-uri").onkeydown = (event) => {
    if (event.key === "Enter") pair();
  };

  $("rule-client").onchange = async (event) => {
    state.client = Number(event.target.value);
    await refreshRules();
  };

  $("activity-more").onclick = () => refreshActivity(true);

  for (const event of [
    "signer://unlocked",
    "signer://locked",
    "signer://client-connected",
    "signer://request-handled",
    "signer://unlock-needed",
  ]) {
    listen(event, refreshAll);
  }
  listen("signer://relay", refreshRelayHealth);
  listen('wallet://received', ({ payload }) => {
    if (state.account === payload) window.WalletUI?.open(true);
  });
  listen('nwc://changed', async () => {
    await refreshPaymentPrompts();
    window.WalletUI?.open(true);
  });
  listen('nwc://unlock-needed', async ({ payload }) => {
    state.account = payload.account;
    await refreshAll();
  });

  // Prompts can appear without an event reaching the window, so poll for them
  // as well. Cheap, and a missed prompt is worse than a redundant read.
  setInterval(refreshPrompts, 1000);
  setInterval(refreshPaymentPrompts, 1000);
  setInterval(refreshRelayHealth, 5000);
}

wire();
refreshAll();
