// Classification is local and descriptive. Pairing requires an explicit Connect
// click; scanning never connects, opens a link, or makes a payment by itself.
(function (root) {
  function describe(raw) {
    const value = raw.trim();
    if (/^nostrconnect:\/\//i.test(value)) return {
      title: "Nostr client connection", action: "pair",
      hint: "", value,
    };
    if (/^bunker:\/\//i.test(value)) return {
      title: "Nostr signer connection",
      hint: "Open in your Nostr app.", value,
    };
    if (/^nostr\+walletconnect:\/\//i.test(value)) return {
      title: "Lightning wallet connection",
      hint: "External wallets are not supported.", value,
    };
    if (/^(cashu:)?cashu[AB][A-Za-z0-9_-]+={0,2}$/.test(value)) return {
      title: "Cashu token", action: "receive",
      hint: "", value,
    };
    if (/^(lightning:)?ln(bc|tb|bcrt)[0-9]+[munp]?1[02-9ac-hj-np-z]+$/i.test(value)
        || /^(lightning:)?ln(bc|tb|bcrt)1[02-9ac-hj-np-z]+$/i.test(value)) return {
      title: "Lightning invoice", action: "pay",
      hint: "", value,
    };
    if (/^(lightning:)?lnurl1[02-9ac-hj-np-z]+$/i.test(value)) return {
      title: "LNURL link",
      hint: "Use a Lightning invoice.", value,
    };
    if (/^(nostr:)?(npub|nprofile|note|nevent|naddr)1[02-9ac-hj-np-z]+$/i.test(value)) return {
      title: "Nostr link", hint: "Open in your Nostr app.", value,
    };
    if (/^(nostr:)?(nsec|ncryptsec)1/i.test(value)) return {
      title: "Private key", hint: "Keep this key private.", value,
    };
    return { title: "QR content", hint: "", value };
  }
  root.CashrQR = { describe };
})(globalThis);
