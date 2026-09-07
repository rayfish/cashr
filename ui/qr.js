// Classification is local and descriptive. Pairing requires an explicit Connect
// click; scanning never connects, opens a link, or makes a payment by itself.
(function (root) {
  function describe(raw) {
    const value = raw.trim();
    if (/^nostrconnect:\/\//i.test(value)) return {
      title: "Nostr client connection", action: "pair",
      hint: "Connect this client using the account selected above.", value,
    };
    if (/^bunker:\/\//i.test(value)) return {
      title: "Nostr signer connection",
      hint: "This link connects a Nostr client to a signer. Paste it into your Nostr client.", value,
    };
    if (/^nostr\+walletconnect:\/\//i.test(value)) return {
      title: "Lightning wallet connection",
      hint: "This link contains wallet credentials. Wallet connections are not available in Byrgi yet.", value,
    };
    if (/^(cashu:)?cashu[AB][A-Za-z0-9_-]+={0,2}$/.test(value)) return {
      title: "Cashu token",
      hint: "This code may contain spendable ecash. Cashu wallets are not available in Byrgi yet.", value,
    };
    if (/^(lightning:)?ln(bc|tb|bcrt)[0-9]+[munp]?1[02-9ac-hj-np-z]+$/i.test(value)
        || /^(lightning:)?ln(bc|tb|bcrt)1[02-9ac-hj-np-z]+$/i.test(value)) return {
      title: "Lightning invoice",
      hint: "Lightning payments are not available in Byrgi yet. No payment has been made.", value,
    };
    if (/^(lightning:)?lnurl1[02-9ac-hj-np-z]+$/i.test(value)) return {
      title: "LNURL link",
      hint: "Lightning services are not available in Byrgi yet. This link has not been opened.", value,
    };
    if (/^(nostr:)?(npub|nprofile|note|nevent|naddr)1[02-9ac-hj-np-z]+$/i.test(value)) return {
      title: "Nostr link", hint: "Paste this code into a Nostr client to view it.", value,
    };
    if (/^(nostr:)?(nsec|ncryptsec)1/i.test(value)) return {
      title: "Private key", hint: "This code contains secret key material. Keep it private.", value,
    };
    return { title: "QR content", hint: "Review the text below. Links are not opened automatically.", value };
  }
  root.ByrgiQR = { describe };
})(globalThis);
