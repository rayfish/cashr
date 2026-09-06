const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

const state = {
  accounts: [],
  account: null,
  clients: [],
  client: null,
  activityCursor: null,
  unlocked: false,
};

const $ = (id) => document.getElementById(id);

function showError(message) {
  const box = $("error");
  if (!message) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  box.textContent = message;
}

async function call(command, args) {
  try {
    const result = await invoke(command, args);
    showError(null);
    return result;
  } catch (error) {
    showError(String(error));
    throw error;
  }
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function shorten(hex) {
  return hex.length > 16 ? `${hex.slice(0, 10)}…${hex.slice(-6)}` : hex;
}

function when(seconds) {
  return new Date(seconds * 1000).toLocaleString();
}

// ------------------------------------------------------------------- prompts

async function refreshPrompts() {
  const prompts = await call("prompts");
  const box = $("prompts");
  box.replaceChildren();
  box.hidden = prompts.length === 0;

  for (const prompt of prompts) {
    const row = el("div", "prompt");
    const grow = el("div", "grow");
    grow.append(
      el("div", null, `${prompt.client_name ?? shorten(prompt.client_public_key)} wants to ${prompt.detail}`),
      el("div", "mono", `${prompt.account_label} · ${prompt.method}`),
    );

    const once = el("button", "primary", "Allow once");
    once.onclick = () => answer(prompt.id, true, false);
    const always = el("button", null, "Always");
    always.onclick = () => answer(prompt.id, true, true);
    const deny = el("button", "danger", "Deny");
    deny.onclick = () => answer(prompt.id, false, false);

    row.append(grow, once, always, deny);
    box.append(row);
  }
}

async function answer(id, allow, remember) {
  await call("answer_prompt", { id, allow, remember });
  await refreshPrompts();
}

// ------------------------------------------------------------------ accounts

async function refreshStatus() {
  const status = await call("status");
  state.unlocked = status.unlocked;
  state.accounts = status.accounts;
  if (!state.account || !state.accounts.some((a) => a.id === state.account)) {
    state.account = state.accounts.find((a) => a.is_default)?.id ?? state.accounts[0]?.id ?? null;
  }

  const pill = $("lock-state");
  pill.textContent = status.unlocked ? "unlocked" : "locked";
  pill.classList.toggle("is-unlocked", status.unlocked);
  $("lock-toggle").textContent = status.unlocked ? "Lock" : "Unlock";

  renderAccounts();
}

function renderAccounts() {
  const list = $("account-list");
  list.replaceChildren();

  for (const account of state.accounts) {
    const card = el("div", "card");
    const grow = el("div", "grow");
    grow.append(
      el("div", null, account.label + (account.is_default ? " (default)" : "")),
      el("div", "mono", account.npub),
    );

    const select = el("button", null, account.id === state.account ? "Selected" : "Select");
    select.onclick = async () => {
      state.account = account.id;
      await refreshAll();
    };

    const makeDefault = el("button", null, "Default");
    makeDefault.onclick = async () => {
      await call("set_default_account", { account: account.id });
      await refreshStatus();
    };

    const remove = el("button", "danger", "Delete");
    remove.onclick = async () => {
      if (!confirm(`Delete ${account.label}? Its key is removed from the Keychain.`)) return;
      await call("delete_account", { account: account.id });
      await refreshAll();
    };

    card.append(grow, select, makeDefault, remove);
    list.append(card);
  }

  renderRelays();
}

function renderRelays() {
  const list = $("relay-list");
  list.replaceChildren();
  const account = state.accounts.find((a) => a.id === state.account);
  if (!account) return;

  for (const url of account.relays) {
    const card = el("div", "card");
    card.append(el("span", "dot"), el("span", "grow mono", url));
    const remove = el("button", "danger", "Remove");
    remove.onclick = async () => {
      const relays = account.relays.filter((r) => r !== url);
      await call("set_relays", { account: account.id, relays });
      await refreshStatus();
    };
    card.append(remove);
    list.append(card);
  }

  refreshRelayHealth();
}

async function refreshRelayHealth() {
  if (state.account === null) return;
  const health = await call("relay_health", { account: state.account });
  const cards = [...$("relay-list").children];
  for (const card of cards) {
    const url = card.querySelector(".mono").textContent;
    const entry = health.find((h) => h.url === url);
    const dot = card.querySelector(".dot");
    dot.classList.toggle("is-up", Boolean(entry?.connected));
    dot.title = entry?.connected ? "connected" : (entry?.last_error ?? "not connected");
  }
}

// ------------------------------------------------------------------- clients

async function refreshClients() {
  if (state.account === null) {
    state.clients = [];
  } else {
    state.clients = await call("clients", { account: state.account });
  }

  const list = $("client-list");
  list.replaceChildren();

  for (const client of state.clients) {
    const card = el("div", "card");
    const grow = el("div", "grow");
    grow.append(
      el("div", null, client.name ?? "Unnamed client"),
      el("div", "mono", `${shorten(client.public_key)} · last seen ${when(client.last_seen)}`),
    );
    card.append(grow);

    if (client.revoked) {
      card.append(el("span", "pill", "revoked"));
    } else {
      const revoke = el("button", "danger", "Revoke");
      revoke.onclick = async () => {
        await call("revoke_client", { client: client.id });
        await refreshClients();
        await refreshRules();
      };
      card.append(revoke);
    }
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
  if (state.client !== null) picker.value = String(state.client);
}

// --------------------------------------------------------------------- rules

async function refreshRules() {
  const list = $("rule-list");
  list.replaceChildren();
  if (state.client === null) return;

  const rules = await call("rules", { client: state.client });
  if (rules.length === 0) {
    list.append(el("div", "hint", "No stored rules. Every request will ask."));
    return;
  }

  for (const rule of rules) {
    const card = el("div", "card");
    const label = rule.kind === null ? rule.method : `${rule.method} · kind ${rule.kind}`;
    card.append(
      el("span", "grow", label),
      el("span", "pill", rule.allow ? "allow" : "deny"),
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
      await call("clear_rule", { client: state.client, method: rule.method, kind: rule.kind });
      await refreshRules();
    };

    card.append(flip, clear);
    list.append(card);
  }
}

// ------------------------------------------------------------------ activity

async function refreshActivity(append = false) {
  if (state.account === null) return;
  if (!append) {
    state.activityCursor = null;
    $("activity-list").replaceChildren();
  }

  const entries = await call("activity", {
    account: state.account,
    limit: 25,
    before: state.activityCursor,
  });

  const list = $("activity-list");
  for (const entry of entries) {
    const card = el("div", "card");
    const grow = el("div", "grow");
    const what = entry.kind === null ? entry.method : `${entry.method} · kind ${entry.kind}`;
    grow.append(el("div", null, what), el("div", "mono", `${when(entry.at)} · ${entry.source}`));
    card.append(grow, el("span", "pill", entry.outcome));
    list.append(card);
  }

  state.activityCursor = entries.at(-1)?.id ?? state.activityCursor;
  $("activity-more").hidden = entries.length < 25;
}

// --------------------------------------------------------------------- wiring

async function refreshAll() {
  await refreshStatus();
  await refreshClients();
  await refreshRules();
  await refreshActivity();
  await refreshPrompts();
}

function wire() {
  for (const tab of document.querySelectorAll(".tab")) {
    tab.onclick = () => {
      for (const other of document.querySelectorAll(".tab")) {
        other.classList.toggle("is-active", other === tab);
      }
      for (const panel of document.querySelectorAll(".panel")) {
        panel.classList.toggle("is-active", panel.id === `tab-${tab.dataset.tab}`);
      }
    };
  }

  $("lock-toggle").onclick = async () => {
    await call(state.unlocked ? "lock" : "unlock");
    await refreshAll();
  };

  $("account-create").onclick = async () => {
    const label = $("account-label").value.trim() || "Account";
    await call("create_account", { label });
    $("account-label").value = "";
    await refreshAll();
  };

  $("account-import").onclick = async () => {
    const label = $("account-label").value.trim() || "Imported";
    const secret = $("account-secret").value.trim();
    if (!secret) return;
    await call("import_account", { label, secret });
    $("account-secret").value = "";
    $("account-label").value = "";
    await refreshAll();
  };

  $("relay-add").onclick = async () => {
    const account = state.accounts.find((a) => a.id === state.account);
    const url = $("relay-url").value.trim();
    if (!account || !url) return;
    await call("set_relays", { account: account.id, relays: [...account.relays, url] });
    $("relay-url").value = "";
    await refreshStatus();
  };

  $("pair-bunker").onclick = async () => {
    if (state.account === null) return;
    const uri = await call("pair_bunker", { account: state.account });
    $("pair-output").textContent = uri;
    await navigator.clipboard.writeText(uri).catch(() => {});
  };

  $("pair-client").onclick = async () => {
    const uri = $("pair-uri").value.trim();
    if (state.account === null || !uri) return;
    await call("pair_client", { account: state.account, uri });
    $("pair-uri").value = "";
    $("pair-output").textContent = "Waiting for the client to connect.";
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

  // Prompts can appear without an event reaching the window, so poll for them
  // as well. Cheap, and a missed prompt is worse than a redundant read.
  setInterval(refreshPrompts, 1000);
  setInterval(refreshRelayHealth, 5000);
}

wire();
refreshAll();
