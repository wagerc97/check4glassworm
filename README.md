# check4glassworm

Bash script to check for any traces of the glassworm as of March, 2026. 

## What is the glassworm?

GlassWorm is a malware campaign ongoing since one year now. It hides malicious code inside invisible Unicode characters within VS Code extensions, >150 GitHub repositories, and npm packages, using stolen developer credentials to automatically compromise additional projects and spread in a self-replicating, worm-like fashion. The Hacker News 

As of March, 2026, it has begun force-pushing malware directly into Python repositories — including ML research code and PyPI packages — by injecting obfuscated payloads into files like setup.py and main.py, meaning anyone who clones and runs an affected repo, or installs from it via pip, can trigger the malware without any visible warning. The Hacker News

For a full review on the one year long campaign of this worm: https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode (2026-03-13) 


## Recommended Actions

- Make an audit of your installed extensions. Check for abnormal activity such as suspicious network connections, vulnerable dependencies and strange API usage.
- Scan new extensions before you install them.
- Only install extensions you need, and remove extensions that are no longer in use. Each installed extension extends your attack surface.
- Evaluate extensions before installing them, check for reviews, extension history, publisher reputation etc.
- Be careful when using auto-update, a compromised extension might install malware when auto-update is turned on.
- Keep an extension inventory.
- Consider a centralized allowlist for VSCode extensions.

(
    [truesec, 2025-10-21](https://www.truesec.com/hub/blog/glassworm-self-propagating-vscode-extension), 
)


## References

**2026**
- https://thehackernews.com/2026/03/glassworm-malware-uses-solana-dead.html (2026-03-25) 
- Video explanation: https://www.youtube.com/watch?v=ZrD9MC_BXGk  (2026-03-24)
- https://thehackernews.com/2026/03/glassworm-attack-uses-stolen-github.html  (2026-03-16) 
- https://thehackernews.com/2026/03/glassworm-supply-chain-attack-abuses-72.html  (2026-03-14)

**2025**
- https://www.truesec.com/hub/blog/glassworm-self-propagating-vscode-extension (2025-10-21)