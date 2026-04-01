# check4glassworm

The bash script [**check_glassworm.sh**](./check_glassworm.sh) checks for any known traces of the glassworm as of March, 2026. 

## What is the glassworm?

GlassWorm is a malware campaign ongoing since one year now. It hides malicious code inside invisible Unicode characters within VS Code extensions, >150 GitHub repositories, and npm packages, using stolen developer credentials to automatically compromise additional projects and spread in a self-replicating, worm-like fashion. The Hacker News 

As of March, 2026, it has begun force-pushing malware directly into Python repositories — including ML research code and PyPI packages — by injecting obfuscated payloads into files like setup.py and main.py, meaning anyone who clones and runs an affected repo, or installs from it via pip, can trigger the malware without any visible warning. The Hacker News

For a full review on the one year long campaign of this worm: https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode (2026-03-13) 


## Recommended Actions

### Self-check 

You can use the [**check_glassworm.sh**](./check_glassworm.sh) script to check your environment for any traces of the glassworm.
The script **performs different checks depending on its parent directory** (i.e. whether it is a git repository, a Python package, etc.). 

### General recommendations: 

- Make an audit of your installed extensions. Check for abnormal activity such as suspicious network connections, vulnerable dependencies and strange API usage.
- Scan new extensions before you install them.
- Only install extensions you need, and remove extensions that are no longer in use. Each installed extension extends your attack surface.
- Evaluate extensions before installing them, check for reviews, extension history, publisher reputation etc.
- Be careful when using auto-update, a compromised extension might install malware when auto-update is turned on.
- Keep an extension inventory.
- Consider a centralized allowlist for VSCode extensions.
- Pin your dependencies, use a lockfile (e.g. for Poetry poetry.lock, or for micromamba/conda environment.yml). This way you get the exact same versions every time, not surprise updates.
- Prefer conda-forge over PyPI: Try to install Python packages from the conda-forge package index rather than PyPI. The micromamba/conda packages on the conda-forge index go through more review. Use pip only for what conda-forge doesn't have.
- Regularly run pip-audit to find known vulnerabilities. If any found, changing these packages' version is recommended. To install pip-audit and run it, run `pip install pip-audit && pip-audit`
- Use virtual environments. They contain installed packages in a single place, which limits the "blast radius" of any potential attack. Don’t install into system python environment



(
    [thehackernews | 2026-03-16](https://thehackernews.com/2026/03/glassworm-attack-uses-stolen-github.html),
    [truesec | 2025-10-21](https://www.truesec.com/hub/blog/glassworm-self-propagating-vscode-extension)
)


## References

**2026**
- https://thehackernews.com/2026/03/glassworm-malware-uses-solana-dead.html (2026-03-25) 
- Video explanation: https://www.youtube.com/watch?v=ZrD9MC_BXGk  (2026-03-24)
- https://thehackernews.com/2026/03/glassworm-attack-uses-stolen-github.html  (2026-03-16) 
- https://thehackernews.com/2026/03/glassworm-supply-chain-attack-abuses-72.html  (2026-03-14)

**2025**
- https://www.truesec.com/hub/blog/glassworm-self-propagating-vscode-extension (2025-10-21)


## Expansion
Please, feel free to contribute to this project by opening an issues or reaching out to. 

