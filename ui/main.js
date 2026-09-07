const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

const state = {
  accounts: [],
  account: null,
  clients: [],
  client: null,
  activityCursor: null,
  unlocked: false,
  needsMigration: false,
  hasKeychainCopies: false,
  hasTouchId: false,
  tab: "home",
  // Where the gear goes back to.
  lastTab: "home",
  pending: 0,
  health: [],
  pinned: false,
  busy: 0,
  savingAccount: false,
  scanning: false,
  preparingScan: false,
  connectingScan: false,
  scanGeneration: 0,
  scanLastTab: "home",
};

const $ = (id) => document.getElementById(id);

// --------------------------------------------------------------- the window

/// The window hides itself when it loses focus. It must not do that while an
/// approval is waiting, while the pin is down, or while a command that raises
/// a system dialog of its own is in flight: Touch ID takes the focus away, and
/// the window would vanish mid-unlock.
function syncPinned() {
  const wanted = state.pinned || state.busy > 0 || state.pending > 0;
  if (wanted === syncPinned.last) return;
  syncPinned.last = wanted;
  invoke("set_pinned", { pinned: wanted }).catch(() => {});
}

async function call(command, args) {
  state.busy += 1;
  syncPinned();
  try {
    const result = await invoke(command, args);
    return result;
  } catch (error) {
    toast(String(error));
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
    prompts.length === 0 ? "" : `${prompts.length} waiting`;

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

async function answer(id, allow, remember) {
  await call("answer_prompt", { id, allow, remember });
  await refreshPrompts();
  if (remember) await refreshRules();
}

// ----------------------------------------------------------------- accounts

async function refreshStatus() {
  const status = await call("status");
  state.unlocked = status.unlocked;
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

  $("lock-dot").className = `dot ${state.unlocked ? "is-up" : "is-down"}`;
  const toggle = $("lock-toggle");
  toggle.textContent = state.unlocked ? "Lock" : "Unlock";
  toggle.title = state.unlocked
    ? "Forget the keys until the next unlock"
    : "Decrypt the keys with your passphrase";

  renderUnlock();
  renderAccountPicker();
  renderAccountCard();
  renderAccountList();
  renderRelays();
}

/// The passphrase box, and what it is for this time.
///
/// Setting a passphrase and giving one are the same box with the same button,
/// because they are the same act from where the user is standing. Only the
/// words above it change, and they have to: one of them cannot be got wrong
/// twice, and the other cannot be got wrong at all.
function renderUnlock() {
  const panel = $("unlock");
  panel.hidden = state.unlocked;
  $("unlock-error").hidden = true;

  const fresh = state.accounts.length === 0;
  const migrating = state.needsMigration && !fresh;
  const setting = fresh || migrating;

  $("unlock-title").textContent = setting ? "Choose a passphrase" : "Unlock";
  $("unlock-hint").textContent = migrating
    ? "Your keys move out of the Keychain and into files encrypted with this. There is no way to recover it, and no way in without it."
    : setting
      ? "Your keys will be encrypted with this. There is no way to recover it, and no way in without it."
      : "Your keys are encrypted with this.";
  $("unlock-passphrase").autocomplete = setting
    ? "new-password"
    : "current-password";
  $("unlock-go").textContent = setting ? "Set and unlock" : "Unlock";

  // Touch ID is an alternative to typing, not to knowing: the box stays
  // whatever the sensor says, because a finger that will not read is the
  // moment the passphrase has to be reachable without hunting for it.
  $("unlock-touch-id").hidden = !(state.hasTouchId && !setting);

  // Nothing to remember while setting one either: the passphrase is stored
  // only after it has opened something, and there is nothing to open yet.
  const offerRemember = !state.hasTouchId && !setting;
  $("unlock-remember-row").hidden = !offerRemember;
  $("unlock-remember-hint").hidden = !offerRemember;
  if (!state.hasTouchId) $("unlock-remember").checked = false;

  // Only worth offering once the keys are safely somewhere else.
  $("keychain-leftover").hidden = !(state.unlocked && state.hasKeychainCopies);

  $("touch-id-badge").textContent = state.hasTouchId ? "Enabled" : "Off";
  $("touch-id-badge").className = `pill ${state.hasTouchId ? "is-allow" : ""}`;
  $("touch-id-state").textContent = state.hasTouchId
    ? "Unlock with Touch ID using a passphrase saved on this Mac. Anyone who can read that file can open your keys. Turning this off removes the saved passphrase."
    : "Unlock with your passphrase. To enable Touch ID, select “Unlock with Touch ID next time” when unlocking. This saves your passphrase on this Mac.";
  $("forget-touch-id").hidden = !state.hasTouchId;
  syncAccountForm();
}

/// Unlock by asking the Keychain for the passphrase, behind Touch ID.
///
/// Same pinning and same error line as typing it: from the user's side this is
/// the same act done with a finger.
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
    await invoke("unlock_with_touch_id");
    await refreshAll();
  } catch (failure) {
    error.textContent = String(failure);
    error.hidden = false;
    // A cancelled prompt leaves Touch ID set up, a rejected passphrase does
    // not. Either way the answer comes from the backend, so ask again.
    await refreshStatus();
  } finally {
    state.busy -= 1;
    syncPinned();
    button.disabled = false;
    button.textContent = label;
  }
}

async function submitUnlock() {
  const field = $("unlock-passphrase");
  const passphrase = field.value;
  if (passphrase === "") return;

  const error = $("unlock-error");
  const button = $("unlock-go");
  const label = button.textContent;
  button.disabled = true;
  button.textContent = "Working…";
  error.hidden = true;

  // Pinned by hand rather than through `call`, which toasts: a wrong
  // passphrase belongs under the box it was typed in, not in a corner. The pin
  // matters because migrating still reads the Keychain, and that prompt takes
  // the focus, which would send the window away mid-unlock.
  state.busy += 1;
  syncPinned();
  try {
    // scrypt takes about a second per key by design, so the window has to say
    // it is doing something or it reads as broken.
    await invoke("unlock", {
      passphrase,
      remember: $("unlock-remember").checked,
    });
    field.value = "";
    await refreshAll();
  } catch (failure) {
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

  card.className = "card stack";
  if (!account) {
    const add = el("button", "primary start", "Add account in Settings");
    add.onclick = () => {
      if (state.tab !== "settings") toggleSettings();
      showAccountForm(true);
    };
    card.append(
      el("div", "title", "Add your first account"),
      empty("Create a new identity or import an existing private key to get started."),
      add,
    );
    return;
  }

  const head = el("div", "card-head");
  head.append(
    el("span", "grow title", account.label),
    el(
      "span",
      `pill ${state.unlocked ? "is-allow" : ""}`,
      state.unlocked ? "unlocked" : "locked",
    ),
  );

  const key = el("div", "mono", account.npub);
  key.title = account.npub;

  const copyKey = el("button", "ghost start", "Copy npub");
  copyKey.onclick = () => copy(account.npub, copyKey);

  card.append(head, key, copyKey);
}

function renderAccountList() {
  const list = $("account-list");
  list.replaceChildren();
  if (state.accounts.length === 0) {
    list.append(empty("No accounts yet. Add one to get started."));
    return;
  }

  for (const account of state.accounts) {
    const card = el("div", "card");
    const grow = el("div", "grow");
    grow.append(el("div", null, account.label), el("div", "mono", account.npub));
    card.append(grow);

    if (account.is_default) {
      card.append(el("span", "pill", "default"));
    } else {
      const makeDefault = el("button", null, "Make default");
      makeDefault.onclick = async () => {
        await call("set_default_account", { account: account.id });
        await refreshStatus();
      };
      card.append(makeDefault);
    }

    const remove = el("button", "danger", "Delete");
    arm(remove, "Delete", async () => {
      await call("delete_account", { account: account.id });
      await refreshAll();
    });
    card.append(remove);

    list.append(card);
  }
}

// -------------------------------------------------------------------- relays

function renderRelays() {
  const list = $("relay-list");
  list.replaceChildren();
  const account = currentAccount();
  if (!account) return;
  if (account.relays.length === 0) {
    list.append(empty("No relays. Nothing can reach this account."));
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
    total === 0 ? "no relays" : `${up}/${total} relays connected`;
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
    list.append(empty("No client has connected yet. Pair one from the Account tab."));
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
    list.append(empty("No clients, so no rules."));
    return;
  }

  const rules = await call("rules", { client: state.client });
  if (rules.length === 0) {
    list.append(empty("Nothing stored. Every request asks first."));
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
  if (state.account === null) return;

  const entries = await call("activity", {
    account: state.account,
    limit: 25,
    before: state.activityCursor,
  });

  if (!append && entries.length === 0) {
    list.append(empty("Nothing yet."));
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

function syncAccountForm() {
  const busy = state.savingAccount;
  $("account-create").disabled = busy || !state.unlocked;
  $("account-import").disabled = busy || !state.unlocked;
  $("account-label").disabled = busy;
  $("account-secret").disabled = busy;
  $("account-cancel").disabled = busy;
  $("account-add").disabled = busy;
  $("account-locked-hint").hidden = state.unlocked;
}

function showAccountForm(shown) {
  $("account-new").hidden = !shown;
  $("account-add").setAttribute("aria-expanded", String(shown));
  if (shown) {
    $("account-label").focus();
  } else {
    $("account-label").value = "";
    $("account-secret").value = "";
  }
}

async function saveAccount(importing) {
  if (state.savingAccount || !state.unlocked) return;
  const label = $("account-label").value.trim() || (importing ? "Imported" : "Account");
  const secret = $("account-secret").value.trim();
  if (importing && !secret) {
    $("account-secret").focus();
    return;
  }
  const button = $(importing ? "account-import" : "account-create");
  const originalLabel = button.textContent;
  state.savingAccount = true;
  button.textContent = importing ? "Importing…" : "Creating…";
  syncAccountForm();
  try {
    await call(importing ? "import_account" : "create_account", importing ? { label, secret } : { label });
    showAccountForm(false);
    await refreshAll();
  } catch {
    // `call` reports the error; keep the form available for correction.
  } finally {
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
      : "For screen selection, allow Byrgi in System Settings → Privacy & Security → Screen Recording. You can still paste an image.";
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

function toggleScanner() {
  if (state.tab === "scan") {
    if (state.scanning || state.connectingScan) return;
    selectTab(state.scanLastTab);
    $("scan-toggle").focus();
  } else {
    state.scanLastTab = state.tab;
    selectTab("scan");
    $("scan-screen").focus();
    prepareScanner();
  }
}

async function connectScannedClient(uri, button) {
  if (state.connectingScan) return;
  if (state.account === null) return toast("Add an account in Settings first.");
  if (!state.unlocked) return toast("Unlock Byrgi above before connecting.");
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
    const result = ByrgiQR.describe(raw);
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

function selectTab(name) {
  if (state.tab === "scan" && name !== "scan") clearScan();
  if (state.tab === "settings" && name !== "settings") showAccountForm(false);
  state.tab = name;
  for (const tab of document.querySelectorAll(".tab")) {
    tab.classList.toggle("is-active", tab.dataset.tab === name);
  }
  for (const panel of document.querySelectorAll(".panel")) {
    panel.classList.toggle("is-active", panel.id === `tab-${name}`);
  }
  // Settings is reached by the gear, so no tab lights up while it is open and
  // the gear has to say where you are instead.
  $("settings-toggle").setAttribute("aria-pressed", String(name === "settings"));
  $("scan-toggle").setAttribute("aria-pressed", String(name === "scan"));
  $("scroll").scrollTop = 0;
}

/// The gear is a toggle, not a fifth tab.
///
/// Settings is somewhere you go and come back from, so closing it returns to
/// the tab you were reading rather than to whichever one is first.
function toggleSettings() {
  if (state.tab === "settings") {
    selectTab(state.lastTab);
    return;
  }
  state.lastTab = state.tab;
  selectTab("settings");
}

async function refreshAll() {
  await refreshStatus();
  await refreshClients();
  await refreshRules();
  await refreshActivity();
  await refreshPrompts();
  await refreshRelayHealth();
}

function wire() {
  $("scan-toggle").onclick = toggleScanner;
  $("scan-screen").onclick = () => scanQR("screen");
  $("scan-clipboard").onclick = () => scanQR("clipboard");
  document.addEventListener("paste", (event) => {
    if (state.tab !== "scan" || event.target?.matches("input, textarea")) return;
    event.preventDefault();
    scanQR("clipboard");
  });
  for (const tab of document.querySelectorAll(".tab")) {
    tab.onclick = () => selectTab(tab.dataset.tab);
  }

  $("settings-toggle").onclick = () => toggleSettings();
  $("settings-done").onclick = () => {
    toggleSettings();
    $("settings-toggle").focus();
  };

  $("account-picker").onchange = async (event) => {
    state.account = Number(event.target.value);
    await refreshAll();
  };

  $("lock-toggle").onclick = async () => {
    if (state.unlocked) {
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
    $("unlock-passphrase").focus();
  };

  $("unlock-touch-id").onclick = () => unlockWithTouchId();

  $("unlock-form").onsubmit = (event) => {
    event.preventDefault();
    submitUnlock();
  };

  arm($("forget-keychain"), "Delete the Keychain copies", async () => {
    await call("forget_keychain");
    await refreshAll();
  });

  arm($("forget-touch-id"), "Stop unlocking with Touch ID", async () => {
    await call("forget_touch_id");
    await refreshAll();
  });

  const pin = $("pin-toggle");
  pin.onclick = () => {
    state.pinned = !state.pinned;
    pin.setAttribute("aria-pressed", String(state.pinned));
    syncPinned();
  };

  $("close").onclick = () => {
    clearScan();
    invoke("hide_window").catch(() => {});
  };

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && state.tab === "scan") {
      event.preventDefault();
      toggleScanner();
      return;
    }
    if (event.key === "Escape" && !state.pinned) {
      invoke("hide_window").catch(() => {});
    }
  });

  $("account-add").onclick = () => showAccountForm($("account-new").hidden);
  $("account-cancel").onclick = () => {
    showAccountForm(false);
    $("account-add").focus();
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

  // Prompts can appear without an event reaching the window, so poll for them
  // as well. Cheap, and a missed prompt is worse than a redundant read.
  setInterval(refreshPrompts, 1000);
  setInterval(refreshRelayHealth, 5000);
}

wire();
refreshAll();
