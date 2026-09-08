// Wallet state is isolated from signer activity. Never cache secrets or tokens.
window.WalletUI = (() => {
  const $ = id => document.getElementById(id);
  const DEFAULT_MINT = 'https://mint.minibits.cash/Bitcoin';
  let invoke, account = null, unlocked = false, busy = false, generation = 0;
  let opened = false, openAttempted = false, review = null, currentView = 'home';
  let backupGeneration = 0, backupTimer;
  let exposureGeneration = 0, sharedOperation = null, incomingRevision = 0;
  let retryTimer, retryDelay = 2000;
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
      return run('wallet_open', {}, render, '');
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
    for (const prefix of ['wallet-share', 'wallet-nostr', 'wallet-invoice']) {
      const canvas = $(prefix + '-qr');
      canvas.width = canvas.height = 0;
      canvas.hidden = true;
      $(prefix + '-qr-error').textContent = '';
    }
    $('wallet-share-token').value = '';
    $('wallet-nostr-uri').value = '';
    $('wallet-nostr-qr-box').hidden = true;
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

  function controls() {
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
    for (const action of ['receive', 'send', 'zap']) $('wallet-show-' + action).disabled = busy || !unlocked || !opened;
  }

  function show(name) {
    hideSecrets();
    clearReview();
    currentView = name;
    for (const panel of document.querySelectorAll('[data-wallet-view]')) {
      panel.hidden = panel.dataset.walletView !== name;
    }
    $('wallet-flow-back').hidden = name === 'home';
    $('wallet-recent').hidden = name !== 'home';
    $('wallet-shortcuts').hidden = name !== 'home';
    $('wallet-overview').hidden = name !== 'home';
    $('wallet-picker').hidden = name !== 'mint' || $('wallet-picker').children.length < 2;
    $('scroll').scrollTop = 0;
    if (name === 'receive' && $('wallet-invoice').value) drawQR($('wallet-invoice').value, 'wallet-invoice');
    controls();
  }

  function sync(selected, isUnlocked) {
    if (account?.id !== selected?.id || unlocked !== isUnlocked) {
      generation++;
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
      $('wallet-token-info').textContent = '';
      incomingRevision++;
      for (const id of ['wallet-invoice', 'wallet-token', 'wallet-request', 'wallet-zap-address', 'wallet-zap-recipient', 'wallet-zap-note']) $(id).value = '';
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
      status.textContent = `${tx.status} · Fee ${tx.fee} sats`;
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
        button.onclick = () => run('wallet_show_token', { operation: token.id }, showTransfer, 'Share this token only once.');
        pending.append(button);
      }
    }
    if (currentView === 'receive' && data.funding_invoice) await drawQR(data.funding_invoice, 'wallet-invoice');
    controls();
    const revision = generation;
    const list = await invoke('wallet_list', { account: account.id });
    if (revision !== generation) return;
    const picker = $('wallet-picker');
    picker.replaceChildren();
    for (const wallet of list.wallets || []) {
      const option = document.createElement('option');
      option.value = wallet.id;
      option.textContent = wallet.label;
      picker.append(option);
    }
    picker.value = list.active;
    picker.hidden = currentView !== 'mint' || (list.wallets || []).length < 2;
  }

  async function run(command, args = {}, apply = render, success = 'Wallet refreshed.') {
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
    $('wallet-status').textContent = command === 'wallet_pay' ? 'Sending payment…'
      : loading ? 'Loading wallet…' : 'Working…';
    try {
      const data = await invoke(command, { ...args, account: selected });
      if (revision !== generation) return;
      if (['wallet_show_token', 'wallet_send_token', 'pair_bunker'].includes(command) && exposure !== exposureGeneration) return;
      await apply(data);
      if (revision !== generation) return;
      if (loading) retryDelay = 2000;
      $('wallet-status').textContent = success;
    } catch (error) {
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
    $('wallet-review').hidden = false;
    $('wallet-confirm').focus();
  }

  function init(call) {
    invoke = call;
    for (const id of ['wallet-request', 'wallet-send-amount', 'wallet-zap-address', 'wallet-zap-recipient', 'wallet-zap-amount', 'wallet-zap-note']) $(id).oninput = clearReview;
    $('wallet-open').onclick = $('wallet-refresh').onclick = () => { clearReview(); return run('wallet_open'); };
    const submit = (id, action) => { $(id).onsubmit = event => { event.preventDefault(); action(); }; };
    for (const view of ['receive', 'send', 'zap', 'nostr']) $('wallet-show-' + view).onclick = () => show(view);
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
      }, '');
    };
    window.addEventListener?.('blur', hideSecrets);
    document.addEventListener?.('visibilitychange', () => { if (document.hidden) hideSecrets(); });
    $('wallet-picker').onchange = () => {
      clearReview();
      run('wallet_select', { slot: $('wallet-picker').value }, render, 'Wallet selected.');
    };
    const chooseMint = () => {
      if (busy || !account || !unlocked) return;
      clearReview();
      return run('wallet_set_mint', { mint: $('wallet-mint-url').value }, async data => {
        const revision = generation;
        await render(data);
        if (revision !== generation) return;
        $('wallet-token').value = '';
        show('home');
      }, 'Mint selected. Existing funds stay at their original mint.');
    };
    submit('wallet-mint-form', chooseMint);
    $('wallet-mint-default').onclick = () => {
      $('wallet-mint-url').value = DEFAULT_MINT;
      return chooseMint();
    };
    submit('wallet-fund-form', () => run('wallet_fund', { amount: Number($('wallet-fund-amount').value) }, async data => {
      $('wallet-invoice').value = data.invoice;
      $('wallet-invoice-box').hidden = false;
      await drawQR(data.invoice, 'wallet-invoice');
    }, 'Refresh after paying.'));
    $('wallet-copy-invoice').onclick = async () => {
      try { await navigator.clipboard.writeText($('wallet-invoice').value); $('wallet-status').textContent = 'Invoice copied.'; }
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
      }, 'Unspent token reclaimed.');
    };
    for (const [button, field] of [['wallet-share-copy', 'wallet-share-token']]) {
      $(button).onclick = async () => {
        if (!$(field).value) return;
        try { await navigator.clipboard.writeText($(field).value); $('wallet-status').textContent = 'Copied.'; }
        catch { $('wallet-status').textContent = 'Select and copy the text above.'; }
      };
    }
    $('wallet-nostr-code').onclick = () => run('pair_bunker', {}, async uri => {
      $('wallet-nostr-uri').value = uri;
      $('wallet-nostr-qr-box').hidden = false;
      await drawQR(uri, 'wallet-nostr');
    }, 'Scan this code from your Nostr app to connect.');
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
    }, 'Bunker URL copied.');
    submit('wallet-nostr-connect-form', () => {
      const uri = $('wallet-nostr-connect-uri').value.trim();
      if (!uri.startsWith('nostrconnect://')) {
        $('wallet-status').textContent = 'Paste a nostrconnect:// link.';
        return;
      }
      return run('pair_client', { uri }, () => {
        $('wallet-nostr-connect-uri').value = '';
      }, 'Nostr app connected.');
    });
    submit('wallet-send-form', () => {
      clearReview();
      return run('wallet_review_send', { amount: Number($('wallet-send-amount').value) }, data => payment(data, 'cashu'), 'Review the amount and fees before creating a token.');
    });
    submit('wallet-receive-form', () => run('wallet_receive', { token: $('wallet-token').value }, data => {
      $('wallet-token').value = ''; return render(data);
    }, 'Token received.'));
    submit('wallet-pay-form', () => { clearReview(); run('wallet_review', { request: $('wallet-request').value }, payment, 'Review the destination, amount, and fees before paying.'); });
    submit('wallet-zap-form', () => {
      clearReview();
      run('wallet_zap', { zap: { address: $('wallet-zap-address').value, recipient: $('wallet-zap-recipient').value, amount: Number($('wallet-zap-amount').value), note: $('wallet-zap-note').value } }, payment, 'Zap request signed. Approve the payment to send funds.');
    });
    $('wallet-confirm').onclick = () => {
      if (busy || !review) return;
      const quote = review.quote;
      const kind = review.kind;
      clearReview();
      if (kind === 'cashu') return run('wallet_send_token', { quote }, async data => {
        const revision = generation, exposure = exposureGeneration;
        await render(data.wallet);
        if (revision === generation && exposure === exposureGeneration) await showTransfer(data.transfer);
      }, 'Token created. Share it once; it stays available in Pending tokens.');
      return run('wallet_pay', { quote }, async data => {
        const revision = generation;
        await render(data);
        if (revision === generation) show('home');
      }, 'Payment submitted. Check its transaction status; Refresh reconciles pending payments.');
    };
    $('wallet-cancel').onclick = () => {
      if (busy) return;
      clearReview();
      invoke('wallet_cancel', { account: account.id }).catch(() => {});
      show('home');
      $('wallet-status').textContent = 'Cancelled.';
    };
    $('wallet-restore').onclick = () => run('wallet_restore', {}, render, 'Recovery finished.');
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
    if (refresh || (!opened && !openAttempted)) return run('wallet_open', {}, render, '');
  }
  return { init, sync, scan, show, open, hideBackup, hideSecrets };
})();
