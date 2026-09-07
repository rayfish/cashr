// Wallet state is isolated from signer activity. Never cache secrets or tokens.
window.WalletUI = (() => {
  const $ = id => document.getElementById(id);
  let invoke, account = null, unlocked = false, busy = false, generation = 0;
  let opened = false, review = null;

  function clearReview() {
    review = null;
    $('wallet-review').hidden = true;
    $('wallet-destination').textContent = '';
  }

  function controls() {
    $('wallet-open').hidden = opened;
    $('wallet-actions').hidden = !opened || !unlocked;
    for (const control of document.querySelectorAll('#tab-wallet button, #tab-wallet input, #tab-wallet textarea, #tab-wallet select')) control.disabled = busy || !unlocked || !account;
    $('wallet-refresh').disabled = busy || !unlocked || !account;
  }

  function sync(selected, isUnlocked) {
    if (account?.id !== selected?.id || unlocked !== isUnlocked) {
      generation++;
      opened = false;
      clearReview();
      $('wallet-balance').textContent = '— sats';
      $('wallet-pending').textContent = '';
      $('wallet-history').replaceChildren();
      for (const id of ['wallet-invoice', 'wallet-token', 'wallet-request', 'wallet-zap-address', 'wallet-zap-recipient', 'wallet-zap-note', 'wallet-import-seed', 'wallet-import-passphrase']) $(id).value = '';
      $('wallet-picker').replaceChildren();
      $('wallet-picker').hidden = true;
      $('wallet-mint').textContent = '';
      $('wallet-invoice-box').hidden = true;
      $('wallet-status').textContent = isUnlocked ? 'Open the wallet for this account.' : 'Unlock this account to open its wallet.';
    }
    account = selected;
    unlocked = isUnlocked;
    $('wallet-account').textContent = account ? `For ${account.label}` : 'Add a Nostr account in Settings first.';
    controls();
  }

  async function render(data) {
    opened = true;
    $('wallet-balance').textContent = `${data.balance.toLocaleString()} sats`;
    $('wallet-pending').textContent = data.pending ? `${data.pending} sats pending or reserved` : '';
    $('wallet-invoice').value = data.funding_invoice || '';
    $('wallet-invoice-box').hidden = !data.funding_invoice;
    $('wallet-mint').textContent = `Mint: ${data.mint || 'btc.aleafnd.org/cashu'}`;
    const history = $('wallet-history');
    history.replaceChildren();
    for (const tx of data.transactions) {
      const row = document.createElement('div');
      row.className = 'card stack';
      row.textContent = `${tx.direction} · ${tx.amount} sats · ${tx.status} · Fee ${tx.fee} sats · ${new Date(tx.timestamp * 1000).toLocaleString()}`;
      history.append(row);
    }
    if (!data.transactions.length) history.textContent = 'No transactions yet.';
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
    picker.hidden = (list.wallets || []).length < 2;
  }

  async function run(command, args = {}, apply = render, success = 'Wallet refreshed.') {
    if (busy || !account || !unlocked) return;
    busy = true;
    controls();
    const revision = generation;
    const selected = account.id;
    $('wallet-status').textContent = command === 'wallet_pay' ? 'Payment in progress. Closing this window will not cancel it.' : 'Working…';
    try {
      const data = await invoke(command, { ...args, account: selected });
      if (revision !== generation) return;
      await apply(data);
      if (revision !== generation) return;
      $('wallet-status').textContent = success;
    } catch (error) {
      if (revision !== generation) return;
      $('wallet-status').textContent = String(error);
    } finally {
      busy = false;
      controls();
    }
  }

  function payment(data) {
    review = data;
    $('wallet-destination').textContent = data.destination;
    $('wallet-review-amount').textContent = `${data.amount} sats`;
    $('wallet-review-fee').textContent = `Fees up to ${data.max_fee} sats. Maximum total: ${data.maximum} sats. Unused fee reserve is returned as change. Expires ${new Date(data.expiry * 1000).toLocaleTimeString()}.`;
    $('wallet-confirm').textContent = `Pay up to ${data.maximum} sats`;
    $('wallet-review').hidden = false;
    $('wallet-confirm').focus();
  }

  function init(call) {
    invoke = call;
    for (const id of ['wallet-request', 'wallet-zap-address', 'wallet-zap-recipient', 'wallet-zap-amount', 'wallet-zap-note']) $(id).oninput = clearReview;
    $('wallet-open').onclick = $('wallet-refresh').onclick = () => { clearReview(); return run('wallet_open'); };
    const submit = (id, action) => { $(id).onsubmit = event => { event.preventDefault(); action(); }; };
    $('wallet-picker').onchange = () => {
      clearReview();
      run('wallet_select', { slot: $('wallet-picker').value }, render, 'Wallet selected.');
    };
    submit('wallet-import-form', () => {
      if (busy || !account || !unlocked) return;
      clearReview();
      const selected = account.id;
      const revision = generation;
      const recovery = { mnemonic: $('wallet-import-seed').value, passphrase: $('wallet-import-passphrase').value, mint: $('wallet-import-mint').value };
      $('wallet-import-seed').value = '';
      $('wallet-import-passphrase').value = '';
      run('wallet_import', { recovery }, async data => {
        await render(data);
        if (revision !== generation) return;
        $('wallet-import-section').open = false;
        $('wallet-status').textContent = 'Wallet saved. Recovering tokens…';
        try {
          const restored = await invoke('wallet_restore', { account: selected });
          if (revision === generation) await render(restored);
        } catch {
          throw new Error('Wallet imported. Recovery could not finish; use Recover tokens from mint to retry.');
        }
      }, 'Wallet imported and recovery finished.');
    });
    submit('wallet-fund-form', () => run('wallet_fund', { amount: Number($('wallet-fund-amount').value) }, data => {
      $('wallet-invoice').value = data.invoice;
      $('wallet-invoice-box').hidden = false;
    }, 'Pay the funding invoice, then Refresh.'));
    $('wallet-copy-invoice').onclick = async () => {
      try { await navigator.clipboard.writeText($('wallet-invoice').value); $('wallet-status').textContent = 'Invoice copied.'; }
      catch { $('wallet-status').textContent = 'Select and copy the invoice above.'; }
    };
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
      clearReview();
      return run('wallet_pay', { quote }, render, 'Payment submitted. Check its transaction status; Refresh reconciles pending payments.');
    };
    $('wallet-cancel').onclick = () => {
      if (busy) return;
      clearReview();
      invoke('wallet_cancel', { account: account.id }).catch(() => {});
      $('wallet-status').textContent = 'Payment cancelled before submission.';
    };
    $('wallet-restore').onclick = () => run('wallet_restore', {}, render, 'Recovery finished.');
  }

  function scan(value) {
    $('wallet-request').value = value;
    $('wallet-pay-section').open = true;
    $('wallet-status').textContent = 'Open the wallet if needed, then review this invoice.';
    $('wallet-request').focus();
  }
  return { init, sync, scan };
})();
