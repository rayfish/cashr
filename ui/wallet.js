// Wallet state is isolated from signer activity. Never cache secrets or tokens.
window.WalletUI = (() => {
  const $ = id => document.getElementById(id);
  const DEFAULT_MINT = 'https://mint.minibits.cash/Bitcoin';
  let invoke, account = null, unlocked = false, busy = false, generation = 0;
  let opened = false, openAttempted = false, review = null, currentView = 'home';
  let backupGeneration = 0, backupTimer;
  let exposureGeneration = 0, sharedOperation = null, incomingRevision = 0;
  let retryTimer, retryDelay = 2000;
  let mintChoices = { wallets: [] }, mintDirectory = [], directoryLoaded = 0, directoryBusy = false;
  const loadCommands = new Set(['wallet_open', 'wallet_select', 'wallet_set_mint', 'wallet_restore']);
  const retryableErrors = new Set(['Mint sync failed. Retrying…', 'Fund recovery interrupted. Retrying…']);

  function cancelRetry() { clearTimeout(retryTimer); retryTimer = null; }

  function retryLoading() {
    cancelRetry();
    const revision = generation;
    retryTimer = setTimeout(() => {
      retryTimer = null;
      if (revision !== generation || !account || !unlocked) return;
      if (busy) return retryLoading();
      return run('wallet_open', {}, render);
    }, retryDelay);
    retryDelay = Math.min(retryDelay * 2, 30000);
  }

  function hideBackup() {
    backupGeneration++;
    clearTimeout(backupTimer);
    $('wallet-words').replaceChildren();
    $('wallet-backup-words').hidden = true;
    $('wallet-backup-unavailable').hidden = true;
    $('wallet-backup-mints').textContent = '';
    $('wallet-backup-passphrase').hidden = true;
  }

  function hideCodes() {
    exposureGeneration++;
    sharedOperation = null;
    for (const prefix of ['wallet-share', 'wallet-nostr', 'wallet-invoice', 'wallet-nwc', 'wallet-address']) {
      const canvas = $(prefix + '-qr');
      canvas.width = canvas.height = 0;
      canvas.hidden = true;
      $(prefix + '-qr-error').textContent = '';
    }
    $('wallet-share-token').value = '';
    $('wallet-nostr-uri').value = '';
    $('wallet-nostr-qr-box').hidden = true;
    $('wallet-nwc-uri').value = '';
    $('wallet-nwc-qr-box').hidden = true;
  }

  function hideSecrets() { hideBackup(); hideCodes(); $('wallet-token').value = ''; $('wallet-nostr-connect-uri').value = ''; incomingRevision++; }

  async function drawQR(value, prefix) {
    if (!value) return;
    const exposure = exposureGeneration, revision = generation;
    try {
      const data = await invoke('encode_qr', { value });
      if (exposure !== exposureGeneration || revision !== generation) return;
      const canvas = $(prefix + '-qr');
      const width = data.width;
      const size = (width + 8) * 4;
      canvas.width = canvas.height = size;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, size, size);
      ctx.fillStyle = '#000';
      for (let y = 0; y < width; y++) for (let x = 0; x < width; x++) {
        if (data.modules[y * width + x]) ctx.fillRect((x + 4) * 4, (y + 4) * 4, 4, 4);
      }
      canvas.hidden = false;
      $(prefix + '-qr-error').textContent = '';
    } catch (error) {
      if (exposure === exposureGeneration && revision === generation) $(prefix + '-qr-error').textContent = String(error);
    }
  }

  async function showTransfer(data) {
    show('token');
    sharedOperation = data.id;
    $('wallet-share-amount').textContent = `${data.amount} sats · ${data.mint}`;
    $('wallet-share-token').value = data.token;
    await drawQR(data.token, 'wallet-share');
    data.token = '';
  }

  async function inspectIncoming() {
    const revision = ++incomingRevision;
    const selected = generation;
    const token = $('wallet-token').value;
    if (!token.trim()) { $('wallet-token-info').textContent = ''; return; }
    try {
      const info = await invoke('wallet_inspect_token', { token });
      if (revision === incomingRevision && selected === generation) $('wallet-token-info').textContent = `${info.amount} sats · ${info.mint}`;
    } catch (error) {
      if (revision === incomingRevision && selected === generation) $('wallet-token-info').textContent = String(error);
    }
  }

  function clearReview() {
    review = null;
    $('wallet-review').hidden = true;
    $('wallet-destination').textContent = '';
  }

  function renderName(data) {
    $('wallet-name-form').hidden = !!data.address || !!data.pending;
    $('wallet-name-owned').hidden = !data.address;
    $('wallet-name-address').textContent = data.address || '';
    $('wallet-name-pending').hidden = !data.pending;
    $('wallet-name-pending-address').textContent = data.pending || '';
    $('wallet-name-retry').hidden = !data.can_retry;
    $('wallet-name-reclaim').hidden = !data.can_reclaim;
  }

  async function nameResult(data) {
    const revision = generation;
    await render(data.wallet);
    if (revision !== generation) return;
    show('name');
    renderName(data.name);
  }

  function controls() {
    $('wallet-refresh').classList?.toggle('is-loading', busy);
    $('tab-wallet').setAttribute('aria-busy', String(busy));
    $('wallet-welcome').hidden = !!account;
    $('wallet-overview').hidden = !account || currentView !== 'home';
    $('wallet-refresh').hidden = !account;
    $('wallet-open').hidden = opened || unlocked;
    $('wallet-actions').hidden = !opened || !unlocked;
    for (const control of document.querySelectorAll('#tab-wallet button, #tab-wallet input, #tab-wallet textarea, #tab-wallet select')) control.disabled = busy || !unlocked || !account;
    $('wallet-refresh').disabled = busy || !unlocked || !account;
    $('wallet-shortcuts').hidden = !account || currentView !== 'home' || !unlocked;
    for (const id of ['wallet-create', 'wallet-import']) $(id).disabled = busy;
    if (!account) {
      $('wallet-flow-back').hidden = true;
      for (const panel of document.querySelectorAll('[data-wallet-view]')) panel.hidden = true;
    }
    for (const action of ['receive', 'send']) $('wallet-show-' + action).disabled = busy || !unlocked || !opened;
  }

  function show(name) {
    hideSecrets();
    clearReview();
    currentView = name;
    if (name === 'nostr') loadConnections();
    for (const panel of document.querySelectorAll('[data-wallet-view]')) {
      panel.hidden = panel.dataset.walletView !== name;
    }
    $('wallet-flow-back').hidden = name === 'home';
    $('wallet-recent').hidden = name !== 'home';
    $('wallet-shortcuts').hidden = name !== 'home';
    $('wallet-overview').hidden = name !== 'home';
    $('wallet-picker').hidden = name !== 'mint';
    $('wallet-mint-form').hidden = true;
    $('wallet-mint-add').hidden = false;
    $('wallet-status').textContent = '';
    $('scroll').scrollTop = 0;
    if (name === 'receive' && $('wallet-invoice').value) drawQR($('wallet-invoice').value, 'wallet-invoice');
    controls();
    if (name === 'mint') loadMintDirectory();
  }

  function sync(selected, isUnlocked) {
    if (account?.id !== selected?.id || unlocked !== isUnlocked) {
      generation++;
      renderName({});
      $('wallet-name-input').value = '';
      cancelRetry();
      retryDelay = 2000;
      opened = false;
      openAttempted = false;
      show('home');
      $('wallet-balance').textContent = '— sats';
      $('wallet-pending').textContent = '';
      $('wallet-history').replaceChildren();
      $('wallet-pending-tokens').replaceChildren();
      $('wallet-pending-tokens').hidden = true;
      $('wallet-nwc-connections').replaceChildren();
      $('wallet-address-value').value = '';
      $('wallet-address-box').hidden = true;
      $('wallet-address-status').textContent = '';
      $('wallet-token-info').textContent = '';
      incomingRevision++;
      for (const id of ['wallet-invoice', 'wallet-token', 'wallet-request']) $(id).value = '';
      $('wallet-picker').replaceChildren();
      $('wallet-picker').hidden = true;
      $('wallet-mint').textContent = '';
      $('wallet-mint-url').value = DEFAULT_MINT;
      $('wallet-invoice-box').hidden = true;
      $('wallet-status').textContent = '';
    }
    account = selected;
    unlocked = isUnlocked;
    $('wallet-account').textContent = account ? `For ${account.label}` : 'Create or restore a wallet in Settings.';
    controls();
  }

  async function render(data) {
    opened = true;
    const address = data.lightning_address?.address || '';
    if ($('wallet-address-value').value !== address) {
      $('wallet-address-qr').hidden = true;
      $('wallet-address-qr').width = $('wallet-address-qr').height = 0;
    }
    $('wallet-address-value').value = address;
    $('wallet-address-box').hidden = !address;
    $('wallet-address-enable').hidden = !!address;
    $('wallet-address-status').textContent = data.receiving_error ? 'Could not sync npub.cash. Retry with Refresh.' : '';
    $('wallet-balance').textContent = `${data.balance.toLocaleString()} sats`;
    $('wallet-pending').textContent = data.pending ? `${data.pending} sats pending or reserved` : '';
    $('wallet-invoice').value = data.funding_invoice || '';
    $('wallet-invoice-box').hidden = !data.funding_invoice;
    $('wallet-mint').textContent = data.mint ? `Mint: ${data.mint}` : '';
    $('wallet-choose-mint-label').textContent = data.mint === DEFAULT_MINT ? 'Minibits' : (data.mint || 'Choose mint');
    const history = $('wallet-history');
    history.replaceChildren();
    for (const tx of data.transactions) {
      const row = document.createElement('div');
      row.className = 'card stack';
      const head = document.createElement('div');
      head.className = 'card-head';
      const direction = document.createElement('span');
      direction.className = 'grow title';
      direction.textContent = tx.direction;
      const amount = document.createElement('span');
      amount.className = 'transaction-amount';
      amount.textContent = `${tx.amount.toLocaleString()} sats`;
      head.append(direction, amount);
      const meta = document.createElement('div');
      meta.className = 'transaction-meta';
      const status = document.createElement('span');
      status.textContent = tx.error || `${tx.status} · Fee ${tx.fee} sats`;
      const date = document.createElement('span');
      date.textContent = new Date(tx.timestamp * 1000).toLocaleString();
      meta.append(status, date);
      row.append(head, meta);
      history.append(row);
    }
    if (!data.transactions.length) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'No transactions yet.';
      history.append(empty);
    }
    const pending = $('wallet-pending-tokens');
    pending.replaceChildren();
    pending.hidden = !(data.pending_tokens || []).length;
    if (!pending.hidden) {
      const title = document.createElement('h2'); title.textContent = 'Pending tokens'; pending.append(title);
      for (const token of data.pending_tokens) {
        const button = document.createElement('button');
        button.textContent = `${token.amount} sats · Show token QR`;
        button.onclick = () => run('wallet_show_token', { operation: token.id }, showTransfer);
        pending.append(button);
      }
    }
    if (currentView === 'receive' && data.funding_invoice) await drawQR(data.funding_invoice, 'wallet-invoice');
    controls();
    const revision = generation;
    const list = await invoke('wallet_list', { account: account.id });
    if (revision !== generation) return;
    renderMints(list);
  }

  function renderMints(list) {
    mintChoices = list;
    const revision = generation;
    const picker = $('wallet-picker');
    picker.replaceChildren();
    const saved = new Map();
    for (const wallet of list.wallets || []) {
      if (!saved.has(wallet.label) || wallet.id === list.active) saved.set(wallet.label, wallet);
    }
    if (!saved.has(DEFAULT_MINT)) saved.set(DEFAULT_MINT, { label: DEFAULT_MINT });
    const mints = [...saved.values()].sort((a, b) => a.label === DEFAULT_MINT ? -1 : b.label === DEFAULT_MINT ? 1 : a.label.localeCompare(b.label));
    const recommendations = mintDirectory.filter(mint => !saved.has(mint.url));
    mints.push(...recommendations.map(mint => ({ label: mint.url, suggested: true })));
    let heading = false;
    for (const mint of mints) {
      if (mint.suggested && !heading) {
        const title = document.createElement('div'); title.className = 'mint-directory-heading';
        const label = document.createElement('span'); label.textContent = 'Top rated';
        const source = document.createElement('a'); source.textContent = 'Cashumints.space';
        source.href = 'https://cashumints.space/mints'; source.target = '_blank'; source.rel = 'noreferrer';
        title.append(label, source); picker.append(title); heading = true;
      }
      const rated = mintDirectory.find(row => row.url === mint.label);
      const button = document.createElement('button');
      button.className = 'mint-row';
      button.type = 'button';
      if (mint.label === DEFAULT_MINT) button.id = 'wallet-mint-default';
      const selected = !!mint.id && mint.id === list.active;
      button.setAttribute('aria-pressed', String(selected));
      button.disabled = busy || !unlocked;
      const name = document.createElement('span');
      name.className = 'mint-description';
      const title = document.createElement('span');
      title.textContent = mint.label === DEFAULT_MINT ? 'Minibits' : rated?.name || mint.label.replace(/^https?:\/\//, '').replace(/\/$/, '');
      name.append(title);
      if (rated) {
        const rating = document.createElement('span'); rating.className = 'mint-rating';
        rating.textContent = `${rated.rating.toFixed(1)} / 5 · ${rated.reviews} reviews`;
        name.append(rating);
      }
      const mark = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      mark.setAttribute('class', 'glyph'); mark.setAttribute('viewBox', '0 0 24 24');
      mark.setAttribute('fill', 'none'); mark.setAttribute('stroke', 'currentColor');
      mark.setAttribute('stroke-width', '1.75'); mark.setAttribute('stroke-linecap', 'round');
      mark.setAttribute('stroke-linejoin', 'round'); mark.setAttribute('aria-hidden', 'true');
      const icon = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      icon.setAttribute('d', selected ? 'm20 6-11 11-5-5' : 'm9 18 6-6-6-6'); mark.append(icon);
      button.append(name, mark);
      button.onclick = () => {
        if (busy || !unlocked || !account || revision !== generation) return;
        if (selected) { show('home'); return; }
        clearReview();
        return run(mint.id ? 'wallet_select' : 'wallet_set_mint', mint.id ? { slot: mint.id } : { mint: mint.label }, async data => {
          const revision = generation;
          await render(data);
          if (revision === generation) show('home');
        });
      };
      picker.append(button);
    }
    picker.hidden = currentView !== 'mint';
  }

  async function loadMintDirectory(force = false) {
    if (directoryBusy || (!force && directoryLoaded && Date.now() - directoryLoaded < 300000)) return;
    const revision = generation;
    directoryBusy = true;
    $('wallet-mints-retry').hidden = true;
    try {
      const rows = await invoke('wallet_mint_directory');
      if (!Array.isArray(rows)) throw new Error('Invalid mint directory');
      mintDirectory = rows; directoryLoaded = Date.now();
      if (revision === generation && currentView === 'mint') renderMints(mintChoices);
    } catch {
      if (revision === generation && currentView === 'mint') $('wallet-mints-retry').hidden = false;
    } finally { directoryBusy = false; controls(); }
  }

  async function loadConnections() {
    if (!account) return;
    const revision = generation;
    try {
      const connections = await invoke('nwc_connections', { account: account.id });
      if (revision !== generation) return;
      const box = $('wallet-nwc-connections');
      box.replaceChildren();
      for (const connection of connections) {
        const row = document.createElement('div'); row.className = 'nwc-connection';
        const name = document.createElement('span'); name.textContent = connection.label;
        const revoke = document.createElement('button'); revoke.textContent = 'Revoke'; revoke.className = 'danger';
        revoke.disabled = busy || !unlocked;
        revoke.onclick = () => run('nwc_revoke', { id: connection.id }, async () => { hideCodes(); await loadConnections(); });
        row.append(name, revoke); box.append(row);
      }
    } catch (error) {
      if (revision === generation) $('wallet-status').textContent = 'Could not load zap connections.';
    }
  }

  async function run(command, args = {}, apply = render) {
    if (busy || !account || !unlocked) return;
    const loading = loadCommands.has(command);
    if (loading) {
      cancelRetry();
      if (command !== 'wallet_open') {
        opened = false;
        hideSecrets();
        clearReview();
        $('wallet-pending').textContent = '';
        $('wallet-history').replaceChildren();
        $('wallet-pending-tokens').replaceChildren();
      }
      if (!opened) $('wallet-balance').textContent = 'Loading…';
    }
    if (command === 'wallet_open') openAttempted = true;
    if (command !== 'wallet_backup') hideBackup();
    busy = true;
    controls();
    const revision = generation;
    const selected = account.id;
    const exposure = exposureGeneration;
    $('wallet-status').textContent = '';
    try {
      const data = await invoke(command, { ...args, account: selected });
      if (revision !== generation) return;
      if (['wallet_show_token', 'wallet_send_token', 'pair_bunker', 'nwc_pair'].includes(command) && exposure !== exposureGeneration) return;
      await apply(data);
      if (revision !== generation) return;
      if (loading) retryDelay = 2000;
      $('wallet-status').textContent = '';
    } catch (error) {
      if (revision !== generation) return;
      if (['wallet_name_claim', 'wallet_name_retry', 'wallet_name_reclaim'].includes(command)) {
        try {
          const name = await invoke('wallet_name_status', { account: selected, refreshProvider: false });
          if (revision !== generation) return;
          show('name');
          renderName(name);
        } catch { /* Preserve the original operation error. */ }
      }
      if (revision !== generation) return;
      if (loading && retryableErrors.has(String(error))) {
        $('wallet-status').textContent = 'Connecting to mint…';
        retryLoading();
      } else {
        if (!opened) $('wallet-balance').textContent = '— sats';
        $('wallet-status').textContent = String(error);
      }
    } finally {
      busy = false;
      controls();
    }
  }

  function payment(data, kind = "lightning") {
    show('review');
    review = { ...data, kind };
    $('wallet-destination').textContent = data.destination;
    $('wallet-review-amount').textContent = `${data.amount} sats`;
    $('wallet-review-fee').textContent = `Fee ≤ ${data.max_fee} sats · Total ≤ ${data.maximum} sats · Expires ${new Date(data.expiry * 1000).toLocaleTimeString()}`;
    if (kind === 'cashu') $('wallet-review-fee').textContent = `Fee ≤ ${data.max_fee} sats · Total ≤ ${data.maximum} sats`;
    $('wallet-confirm').textContent = kind === 'cashu' ? `Create token · up to ${data.maximum} sats` : `Pay up to ${data.maximum} sats`;
    if (kind === 'name') $('wallet-confirm').textContent = data.maximum ? `Claim name · up to ${data.maximum} sats` : 'Claim name';
    $('wallet-review').hidden = false;
    $('wallet-confirm').focus();
  }

  function init(call) {
    invoke = call;
    $('wallet-mints-retry').onclick = () => loadMintDirectory(true);
    $('wallet-address-enable').onclick = () => run('wallet_enable_address');
    $('wallet-address-show').onclick = () => drawQR($('wallet-address-value').value, 'wallet-address');
    $('wallet-address-copy').onclick = async () => {
      const address = $('wallet-address-value').value;
      if (!address) return;
      const revision = generation;
      try { await navigator.clipboard.writeText(address); }
      catch { if (revision === generation) $('wallet-address-status').textContent = 'Select and copy the address.'; }
    };
    for (const id of ['wallet-request', 'wallet-send-amount']) $(id).oninput = clearReview;
    $('wallet-open').onclick = $('wallet-refresh').onclick = () => { clearReview(); return run('wallet_open', { retryReceiving: true }); };
    const submit = (id, action) => { $(id).onsubmit = event => { event.preventDefault(); action(); }; };
    $('wallet-name-open').onclick = () => {
      show('name');
      return run('wallet_name_status', { refreshProvider: true }, renderName);
    };
    submit('wallet-name-form', () => run('wallet_name_review', { name: $('wallet-name-input').value }, data => payment(data, 'name')));
    $('wallet-name-check').onclick = () => run('wallet_name_status', { refreshProvider: true }, renderName);
    $('wallet-name-retry').onclick = () => run('wallet_name_retry', {}, nameResult);
    $('wallet-name-reclaim').onclick = () => run('wallet_name_reclaim', {}, nameResult);
    $('wallet-name-copy').onclick = async () => {
      const address = $('wallet-name-address').textContent;
      if (!address) return;
      const revision = generation;
      try { await navigator.clipboard.writeText(address); }
      catch { if (revision === generation) $('wallet-status').textContent = 'Select and copy the address.'; }
    };
    for (const view of ['receive', 'send', 'nostr']) $('wallet-show-' + view).onclick = () => show(view);
    $('wallet-flow-back').onclick = () => show('home');
    $('wallet-choose-mint').onclick = () => show('mint');
    $('wallet-backup-hide').onclick = hideBackup;
    $('wallet-backup-show').onclick = () => {
      if (busy || !account || !unlocked) return;
      hideBackup();
      const revision = backupGeneration;
      return run('wallet_backup', {}, data => {
        if (revision !== backupGeneration || currentView !== 'backup') return;
        if (!data.words) {
          $('wallet-backup-unavailable').hidden = false;
          return;
        }
        for (const word of data.words.split(' ')) {
          const item = document.createElement('li');
          item.textContent = word;
          $('wallet-words').append(item);
        }
        $('wallet-backup-mints').textContent = `Mints: ${data.mints.join(', ')}`;
        $('wallet-backup-passphrase').hidden = !data.passphrase_required;
        $('wallet-backup-words').hidden = false;
        data.words = null;
        backupTimer = setTimeout(hideBackup, 60_000);
      });
    };
    window.addEventListener?.('blur', hideSecrets);
    document.addEventListener?.('visibilitychange', () => { if (document.hidden) hideSecrets(); });
    const chooseMint = () => {
      if (busy || !account || !unlocked) return;
      clearReview();
      return run('wallet_set_mint', { mint: $('wallet-mint-url').value }, async data => {
        const revision = generation;
        await render(data);
        if (revision !== generation) return;
        $('wallet-token').value = '';
        show('home');
      });
    };
    submit('wallet-mint-form', chooseMint);
    $('wallet-mint-add').onclick = () => {
      $('wallet-mint-add').hidden = true;
      $('wallet-mint-form').hidden = false;
      $('wallet-mint-url').value = '';
      $('wallet-mint-url').focus();
    };
    $('wallet-mint-cancel').onclick = () => {
      $('wallet-mint-form').hidden = true;
      $('wallet-mint-add').hidden = false;
    };
    submit('wallet-fund-form', () => run('wallet_fund', { amount: Number($('wallet-fund-amount').value) }, async data => {
      $('wallet-invoice').value = data.invoice;
      $('wallet-invoice-box').hidden = false;
      await drawQR(data.invoice, 'wallet-invoice');
    }));
    $('wallet-copy-invoice').onclick = async () => {
      try { await navigator.clipboard.writeText($('wallet-invoice').value); $('wallet-status').textContent = ''; }
      catch { $('wallet-status').textContent = 'Select and copy the invoice above.'; }
    };
    $('wallet-token').onchange = inspectIncoming;
    $('wallet-share-hide').onclick = () => show('home');
    $('wallet-share-reclaim').onclick = () => {
      if (busy || !sharedOperation) return;
      const operation = sharedOperation;
      hideCodes();
      const revision = generation;
      return run('wallet_reclaim_token', { operation }, async data => {
        await render(data);
        if (revision === generation) show('home');
      });
    };
    for (const [button, field] of [['wallet-share-copy', 'wallet-share-token']]) {
      $(button).onclick = async () => {
        if (!$(field).value) return;
        try { await navigator.clipboard.writeText($(field).value); $('wallet-status').textContent = ''; }
        catch { $('wallet-status').textContent = 'Select and copy the text above.'; }
      };
    }
    submit('wallet-nwc-form', () => run('nwc_pair', { label: $('wallet-nwc-name').value }, async uri => {
      hideCodes();
      $('wallet-nwc-uri').value = uri;
      $('wallet-nwc-qr-box').hidden = false;
      await drawQR(uri, 'wallet-nwc');
      await loadConnections();
    }));
    $('wallet-nwc-copy').onclick = async () => {
      const uri = $('wallet-nwc-uri').value;
      if (!uri) return;
      const exposure = exposureGeneration;
      try { await navigator.clipboard.writeText(uri); }
      catch { if (exposure === exposureGeneration) $('wallet-status').textContent = 'Select and copy the connection link.'; }
    };
    $('wallet-nostr-code').onclick = () => run('pair_bunker', {}, async uri => {
      $('wallet-nostr-uri').value = uri;
      $('wallet-nostr-qr-box').hidden = false;
      await drawQR(uri, 'wallet-nostr');
    });
    $('wallet-nostr-copy').onclick = () => run('pair_bunker', {}, async uri => {
      hideCodes();
      $('wallet-nostr-uri').value = uri;
      const exposure = exposureGeneration, revision = generation;
      try { await navigator.clipboard.writeText(uri); }
      catch {
        if (exposure !== exposureGeneration || revision !== generation) return;
        $('wallet-nostr-qr-box').hidden = false;
        throw new Error('Select and copy the bunker URL.');
      }
    });
    submit('wallet-nostr-connect-form', () => {
      const uri = $('wallet-nostr-connect-uri').value.trim();
      if (!uri.startsWith('nostrconnect://')) {
        $('wallet-status').textContent = 'Paste a nostrconnect:// link.';
        return;
      }
      return run('pair_client', { uri }, () => {
        $('wallet-nostr-connect-uri').value = '';
      });
    });
    submit('wallet-send-form', () => {
      clearReview();
      return run('wallet_review_send', { amount: Number($('wallet-send-amount').value) }, data => payment(data, 'cashu'));
    });
    submit('wallet-receive-form', () => run('wallet_receive', { token: $('wallet-token').value }, data => {
      $('wallet-token').value = ''; return render(data);
    }));
    submit('wallet-pay-form', () => { clearReview(); run('wallet_review', { request: $('wallet-request').value }, payment); });

    $('wallet-confirm').onclick = () => {
      if (busy || !review) return;
      const quote = review.quote;
      const kind = review.kind;
      clearReview();
      if (kind === 'name') return run('wallet_name_claim', { quote }, nameResult);
      if (kind === 'cashu') return run('wallet_send_token', { quote }, async data => {
        const revision = generation, exposure = exposureGeneration;
        await render(data.wallet);
        if (revision === generation && exposure === exposureGeneration) await showTransfer(data.transfer);
      });
      return run('wallet_pay', { quote }, async data => {
        const revision = generation;
        await render(data);
        if (revision === generation) show('home');
      });
    };
    $('wallet-cancel').onclick = () => {
      if (busy) return;
      const kind = review?.kind;
      clearReview();
      invoke('wallet_cancel', { account: account.id }).catch(() => {});
      show(kind === 'name' ? 'name' : 'home');
      $('wallet-status').textContent = '';
    };
    $('wallet-restore').onclick = () => run('wallet_restore', {}, render);
  }

  function scan(value) {
    if (/^(cashu:)?cashu[AB]/.test(value)) {
      show('receive');
      $('wallet-token').value = value;
      $('wallet-token').focus();
      inspectIncoming();
      return;
    }
    show('send');
    $('wallet-request').value = value;
    $('wallet-status').textContent = '';
    $('wallet-request').focus();
  }
  function open(refresh = false) {
    if (refresh || (!opened && !openAttempted)) return run('wallet_open', {}, render);
  }
  return { init, sync, scan, show, open, hideBackup, hideSecrets };
})();
