# KeyGuard

Local-first encrypted vault for API keys — with a built-in leak scanner
and one-command provider rotation.

## Why

Developers leak API keys. Existing tools stop at "we detected a leak."
KeyGuard closes the loop: detect, identify which of your keys it is,
rotate it with the provider, and walk you through updating every place
it's deployed.

## 30-second pitch

```console
$ pipx install keyguard
$ keyguard init
$ keyguard add STRIPE --provider stripe
$ keyguard scan .
$ keyguard rotate STRIPE
```

Go deeper:

- [Quickstart](quickstart.md)
- [How it works](how-it-works.md) — the crypto in plain English
- [CLI reference](cli.md)
- [Provider matrix](providers.md)
- [FAQ](faq.md)
- [Security disclosure](security.md)
