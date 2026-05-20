<p align="center">
  <img src="https://raw.githubusercontent.com/zauthofficial/zauthSDK/main/assets/z-small.png" alt="" width="80" height="80" />
</p>

<h3 align="center">ZAUTH Staking</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Solana-Mainnet-blueviolet.svg" alt="Solana Mainnet" />
  <img src="https://img.shields.io/badge/Anchor-0.30.1-blue.svg" alt="Anchor" />
  <img src="https://img.shields.io/badge/Token--2022-Compatible-green.svg" alt="Token-2022" />
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" />
</p>

<p align="center">
  On-chain staking contract for $ZAUTH. Stake with time-locked positions, earn epoch-capped dividends from protocol revenue.
</p>

## Program

| | |
|---|---|
| **Program ID** | `zauthsTeNbEN69fEmMVm48D2K3cEHJAtf7vnaU2uBeC` |
| **Network** | Solana Mainnet |
| **Framework** | Anchor 0.30.1 |
| **Token Standard** | Token-2022 (`transfer_checked`, `token_interface`) |

## How It Works

Users stake $ZAUTH tokens with a chosen lock duration (30 days to 1 year). Longer locks earn a higher weight multiplier (1x at 30d, 2x at 365d, linear between). Protocol revenue is distributed as dividends proportional to each staker's weighted share.

Distributions are epoch-capped: your stake only earns dividends for the epochs your lock covers. No ghost rewards after expiry.

### Staking

- Choose a lock duration between `min_lock` and `max_lock`
- Minimum stake enforced on first deposit
- Re-staking settles pending dividends and resets the lock (new lock must be >= remaining)
- Lock duration determines weight multiplier for dividend share

### Dividends

- Admin distributes protocol revenue each epoch (60 days)
- Distribution is proportional to `weighted_amount` across active stakers
- DPT (dividend-per-token) snapshots stored in a 7-slot ring buffer
- Stakers must claim within 7 epochs of lock expiry (420 days at 60d epochs)

### Early Exit

Unstaking before lock expiry incurs a tiered penalty sent to the treasury:

| Lock Remaining | Penalty |
|---|---|
| > 50% | 50% |
| 25-50% | 30% |
| < 25% | 15% |

### Emergency

- Admin can lower `min_lock` (never raise). Setting to 0 enables emergency unlock for all stakers
- `rescue_stake` requires both admin and user signatures
- Pause/unpause controls for staking and unstaking independently

## Security

- All arithmetic uses checked operations (no overflow)
- Floor division on epoch count prevents sub-epoch lock gaming
- Weight multiplier curve is hardcoded and immutable
- Admin cannot access staked tokens, only treasury funds
- Two-step admin transfer (propose + accept)
- `security.txt` embedded per Solana standard

## Building

```bash
anchor build
```

### Reproducible Build (for verification)

```bash
solana-verify build --library-name zauth_staking
```

## License

MIT
