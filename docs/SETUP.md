# Setup Notes

## Windows 11 + WSL2

1. Install Ubuntu on WSL2.
2. Install Python 3.10+.
3. Clone Volatility 3:

```bash
git clone https://github.com/volatilityfoundation/volatility3.git ~/tools/volatility3
```

4. Update `config/config.local.json` with your local `vol.py` path.
5. Install dependencies from `requirements.txt`.

## Notes

- Some plugin output varies by memory image and symbol availability.
- Start with one known sample dump before scaling to full dataset.
