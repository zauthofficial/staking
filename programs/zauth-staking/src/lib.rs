// =====================================================================================
//
//     ###
//                                         ####
//                                    ##     ##
//                                    ##     ##
//                                    ##    ### ##
//      ########  ####     ##   ##  ######  #######
//      ##   ### ####### ####   ##  ######  ###  ###
//      #   ###  ##   ##   ##  ##    ##     ##   ###
//         ###        ##  ##   ##    ##     ##   ##
//        ###    #######  ##   ##   ##      ##   ##
//       ###    ###   ##  ##  ##    ##     ##    ##
//       ##   # ##   ##  ###  ##    ##     ##   ###
//      ##   ## ######## ########  ######  ##   ####
//     ########  ### ###  #### ###  ###    ##    ###
//
//     zauth treasury + staking
//
//     stake $ZAUTH, pick your lock (30d–1yr), earn distributions from protocol revenue.
//     distributions are epoch-capped: you earn only for the epochs your lock covers.
//
//     admin controls treasury funds and distribution timing.
//     admin cannot access staked tokens. only the staker can move their own funds.
//
// =====================================================================================

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked, Burn};
use anchor_spl::associated_token::AssociatedToken;

#[cfg(not(feature = "no-entrypoint"))]
use solana_security_txt::security_txt;

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "ZAUTH Staking",
    project_url: "https://zauth.inc",
    contacts: "email:team@zauth.inc",
    policy: "https://zauth.inc/tos",
    preferred_languages: "en",
    auditors: "zauth"
}

declare_id!("zauthsTeNbEN69fEmMVm48D2K3cEHJAtf7vnaU2uBeC");

// 1e18 — keeps dividend math precise even with tiny amounts or huge stakes
const PRECISION: u128 = 1_000_000_000_000_000_000;

// extra bytes on every account so we don't regret this later (can't resize post-deploy)
const CONFIG_PADDING: usize = 64;
const STAKE_PADDING: usize = 56;
const REFERRAL_PADDING: usize = 64;

// DPT ring buffer size: 7 slots = 7 epochs of history
// max lock = 365d at 60d/epoch = ~7 epochs. 7 slots covers full max lock.
const DPT_SNAPSHOT_SLOTS: usize = 7;

// early exit penalty tiers — hardcoded, immutable
// >50% of lock remaining: 50%
// 25–50% remaining: 30%
// <25% remaining: 15%
const PENALTY_TIER_HIGH_BPS: u64 = 5000;
const PENALTY_TIER_MID_BPS: u64 = 3000;
const PENALTY_TIER_LOW_BPS: u64 = 1500;

// lock duration weight — longer lock = bigger distribution share
// 30d = 1x, 365d = 2x, linear between, clamped at ends
const WEIGHT_MIN_LOCK: i64 = 2_592_000;  // 30 days
const WEIGHT_MAX_LOCK: i64 = 31_536_000; // 365 days
const WEIGHT_BASE_BPS: u64 = 10_000;     // 1.0x
const WEIGHT_MAX_BPS: u64 = 20_000;      // 2.0x

// Token-2022 transfer_checked requires decimals
const ZAUTH_DECIMALS: u8 = 6;

#[program]
pub mod zauth_staking {
    use super::*;

    // --- setup (run once at deploy) ---

    pub fn initialize(
        ctx: Context<Initialize>,
        min_lock: i64,
        max_lock: i64,
        min_stake: u64,
        referral_commission_bps: u16,
        epoch_duration: i64,
    ) -> Result<()> {
        require!(min_lock >= 0, ErrorCode::InvalidParam);
        require!(max_lock >= min_lock, ErrorCode::InvalidParam);
        require!(epoch_duration > 0, ErrorCode::InvalidParam);

        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.pending_admin = Pubkey::default();
        config.zauth_mint = ctx.accounts.zauth_mint.key();

        config.stake_vault = ctx.accounts.stake_vault.key();
        config.treasury_zauth = Pubkey::default();
        config.dividend_vault = Pubkey::default();
        config.referral_pool = Pubkey::default();

        config.total_staked = 0;
        config.total_weighted_staked = 0;
        config.dividend_per_token = 0;
        config.current_epoch = 0;

        config.min_lock = min_lock;
        config.max_lock = max_lock;
        config.min_stake = min_stake;
        config.referral_commission_bps = referral_commission_bps;

        config.staking_paused = true;
        config.unstaking_paused = true;
        config.init_phase = 1;

        config.bump = ctx.bumps.config;
        config.stake_vault_bump = ctx.bumps.stake_vault;
        config.treasury_zauth_bump = 0;
        config.dividend_vault_bump = 0;
        config.referral_pool_bump = 0;

        config.epoch_duration = epoch_duration;
        config.dpt_snapshots = [0u128; DPT_SNAPSHOT_SLOTS];

        Ok(())
    }

    /// Register vaults: 1=treasury_zauth, 2=dividend_vault, 3=referral_pool
    /// Staking unpauses after all 3 are registered (init_phase reaches 4).
    pub fn register_vault(ctx: Context<RegisterVault>, vault_type: u8) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(config.init_phase < 4, ErrorCode::AlreadyInitialized);

        let vault_key = ctx.accounts.vault.key();
        let vault_bump = ctx.bumps.vault;

        match vault_type {
            1 => {
                require!(
                    ctx.accounts.mint.key() == config.zauth_mint,
                    ErrorCode::InvalidMint
                );
                require!(
                    config.treasury_zauth == Pubkey::default(),
                    ErrorCode::AlreadyInitialized
                );
                config.treasury_zauth = vault_key;
                config.treasury_zauth_bump = vault_bump;
            }
            2 => {
                require!(
                    ctx.accounts.mint.key() == config.zauth_mint,
                    ErrorCode::InvalidMint
                );
                require!(
                    config.dividend_vault == Pubkey::default(),
                    ErrorCode::AlreadyInitialized
                );
                config.dividend_vault = vault_key;
                config.dividend_vault_bump = vault_bump;
            }
            3 => {
                require!(
                    ctx.accounts.mint.key() == config.zauth_mint,
                    ErrorCode::InvalidMint
                );
                require!(
                    config.referral_pool == Pubkey::default(),
                    ErrorCode::AlreadyInitialized
                );
                config.referral_pool = vault_key;
                config.referral_pool_bump = vault_bump;
            }
            _ => return Err(ErrorCode::InvalidParam.into()),
        }

        config.init_phase += 1;

        if config.init_phase == 4 {
            config.staking_paused = false;
            config.unstaking_paused = false;
        }

        Ok(())
    }

    // --- staking ---

    /// stake with a chosen lock duration between min_lock and max_lock.
    pub fn stake(ctx: Context<StakeTokens>, amount: u64, lock_seconds: i64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        require!(
            !ctx.accounts.config.staking_paused,
            ErrorCode::StakingPaused
        );

        let config = &ctx.accounts.config;
        let stake_account = &mut ctx.accounts.stake_account;

        // Validate lock duration
        require!(lock_seconds >= config.min_lock, ErrorCode::LockTooShort);
        require!(lock_seconds <= config.max_lock, ErrorCode::LockTooLong);

        // Save old weighted for global total update later
        let old_weighted = stake_account.weighted_amount;

        // Calculate end_epoch from lock duration (floor division — lock < 1 epoch = 0 distributions)
        let epoch_count = lock_seconds
            .checked_div(config.epoch_duration)
            .ok_or(ErrorCode::MathOverflow)?;

        if stake_account.amount == 0 {
            // First-time stake
            require!(amount >= config.min_stake, ErrorCode::BelowMinStake);
            stake_account.owner = ctx.accounts.user.key();
            stake_account.staked_at = Clock::get()?.unix_timestamp;
            stake_account.lock_duration_at_stake = lock_seconds;
            stake_account.last_dividend_per_token = config.dividend_per_token;
            stake_account.bump = ctx.bumps.stake_account;
            stake_account.end_epoch = config.current_epoch
                .checked_add(epoch_count as u64)
                .ok_or(ErrorCode::MathOverflow)?;

            // Compute weighted amount for new stake
            let weight_bps = calculate_weight_bps(lock_seconds)?;
            stake_account.weighted_amount = compute_weighted_amount(amount, weight_bps)?;
        } else {
            // Expire weight if lock ended (settles pending at capped DPT, then drops to 0)
            let expire_now = Clock::get()?.unix_timestamp;
            let _weight_reduction = expire_weight_if_needed(
                stake_account, config.dividend_per_token,
                config.current_epoch, &config.dpt_snapshots, expire_now,
            )?;

            // Adding to existing stake — settle dividends first (using old weighted amount)
            let effective_dpt = get_effective_dpt(
                stake_account.end_epoch, config.current_epoch,
                config.dividend_per_token, &config.dpt_snapshots,
                stake_account.last_dividend_per_token,
            );
            let pending = calculate_pending_dividend(
                stake_account.weighted_amount,
                effective_dpt,
                stake_account.last_dividend_per_token,
            )?;
            stake_account.pending_dividends = stake_account
                .pending_dividends
                .checked_add(pending)
                .ok_or(ErrorCode::MathOverflow)?;
            // Reset to current global DPT so new stake starts fresh (no phantom claimable)
            stake_account.last_dividend_per_token = config.dividend_per_token;

            // Enforce: new lock must be >= remaining lock (no weight gaming)
            let now = Clock::get()?.unix_timestamp;
            let lock_end = stake_account.staked_at
                .checked_add(stake_account.lock_duration_at_stake)
                .ok_or(ErrorCode::MathOverflow)?;
            let remaining = lock_end.saturating_sub(now);
            require!(lock_seconds >= remaining, ErrorCode::LockShorterThanRemaining);

            // Reset lock with new user-chosen duration
            stake_account.staked_at = now;
            stake_account.lock_duration_at_stake = lock_seconds;
            stake_account.end_epoch = config.current_epoch
                .checked_add(epoch_count as u64)
                .ok_or(ErrorCode::MathOverflow)?;

            // Recompute weighted amount for entire new balance with new lock
            let new_total_raw = stake_account
                .amount
                .checked_add(amount)
                .ok_or(ErrorCode::MathOverflow)?;
            let weight_bps = calculate_weight_bps(lock_seconds)?;
            stake_account.weighted_amount = compute_weighted_amount(new_total_raw, weight_bps)?;
        }

        // Transfer ZAUTH from user -> stake vault
        token_interface::transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.user_zauth.to_account_info(),
                    to: ctx.accounts.stake_vault.to_account_info(),
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount,
            ZAUTH_DECIMALS,
        )?;

        stake_account.amount = stake_account
            .amount
            .checked_add(amount)
            .ok_or(ErrorCode::MathOverflow)?;

        let config = &mut ctx.accounts.config;
        config.total_staked = config
            .total_staked
            .checked_add(amount)
            .ok_or(ErrorCode::MathOverflow)?;

        // Update global weighted total: remove old, add new
        config.total_weighted_staked = config
            .total_weighted_staked
            .checked_sub(old_weighted)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(stake_account.weighted_amount)
            .ok_or(ErrorCode::MathOverflow)?;

        Ok(())
    }

    /// unstake after lock expires. full amount, no penalty.
    pub fn unstake(ctx: Context<Unstake>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);

        let config = &ctx.accounts.config;
        let stake_account = &mut ctx.accounts.stake_account;

        // Pause check: allow exit if emergency unlocked (min_lock == 0)
        if config.unstaking_paused && config.min_lock > 0 {
            return Err(ErrorCode::UnstakingPaused.into());
        }

        require!(amount <= stake_account.amount, ErrorCode::InsufficientStake);

        // Expire weight if lock ended (mutates stake_account only)
        let now = Clock::get()?.unix_timestamp;
        let weight_reduction = expire_weight_if_needed(
            stake_account, config.dividend_per_token,
            config.current_epoch, &config.dpt_snapshots, now,
        )?;

        // Lock check: enforce user's chosen lock duration.
        // Emergency unlock (min_lock == 0) bypasses lock entirely.
        let effective_lock = if config.min_lock == 0 {
            0i64 // emergency mode — anyone can exit immediately
        } else {
            stake_account.lock_duration_at_stake
        };
        let unlock_time = stake_account
            .staked_at
            .checked_add(effective_lock)
            .ok_or(ErrorCode::MathOverflow)?;
        require!(now >= unlock_time, ErrorCode::StillLocked);

        // Settle pending dividends (using capped DPT)
        let effective_dpt = get_effective_dpt(
            stake_account.end_epoch, config.current_epoch,
            config.dividend_per_token, &config.dpt_snapshots,
            stake_account.last_dividend_per_token,
        );
        let pending = calculate_pending_dividend(
            stake_account.weighted_amount,
            effective_dpt,
            stake_account.last_dividend_per_token,
        )?;
        stake_account.pending_dividends = stake_account
            .pending_dividends
            .checked_add(pending)
            .ok_or(ErrorCode::MathOverflow)?;
        stake_account.last_dividend_per_token = effective_dpt;

        // Proportional weighted removal (0 if weight already expired)
        let weighted_removed = if stake_account.weighted_amount > 0 {
            (stake_account.weighted_amount as u128)
                .checked_mul(amount as u128)
                .ok_or(ErrorCode::MathOverflow)?
                .checked_div(stake_account.amount as u128)
                .ok_or(ErrorCode::MathOverflow)? as u64
        } else {
            0
        };

        // Transfer full amount — no penalty
        let seeds = &[b"config".as_ref(), &[config.bump]];
        let signer_seeds = &[&seeds[..]];

        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.stake_vault.to_account_info(),
                    to: ctx.accounts.user_zauth.to_account_info(),
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
            ZAUTH_DECIMALS,
        )?;

        stake_account.amount = stake_account
            .amount
            .checked_sub(amount)
            .ok_or(ErrorCode::MathOverflow)?;
        stake_account.weighted_amount = stake_account
            .weighted_amount
            .checked_sub(weighted_removed)
            .ok_or(ErrorCode::MathOverflow)?;

        let config = &mut ctx.accounts.config;
        config.total_staked = config
            .total_staked
            .checked_sub(amount)
            .ok_or(ErrorCode::MathOverflow)?;
        config.total_weighted_staked = config
            .total_weighted_staked
            .checked_sub(weighted_removed)
            .ok_or(ErrorCode::MathOverflow)?;
        // Also apply weight expiry reduction
        if weight_reduction > 0 {
            config.total_weighted_staked = config.total_weighted_staked.saturating_sub(weight_reduction);
        }

        Ok(())
    }

    /// unstake before lock expires. tiered penalty applied, sent to treasury.
    pub fn early_unstake(ctx: Context<EarlyUnstake>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        require!(
            !ctx.accounts.config.unstaking_paused,
            ErrorCode::UnstakingPaused
        );

        let config = &ctx.accounts.config;
        let stake_account = &mut ctx.accounts.stake_account;

        require!(amount <= stake_account.amount, ErrorCode::InsufficientStake);

        let now = Clock::get()?.unix_timestamp;
        let lock_end = stake_account
            .staked_at
            .checked_add(stake_account.lock_duration_at_stake)
            .ok_or(ErrorCode::MathOverflow)?;

        // Must actually be early — if lock expired, use normal unstake
        require!(now < lock_end, ErrorCode::LockAlreadyExpired);

        // Calculate % of lock time remaining
        let total_lock = stake_account.lock_duration_at_stake;
        let elapsed = now
            .checked_sub(stake_account.staked_at)
            .ok_or(ErrorCode::MathOverflow)?;
        let remaining = total_lock
            .checked_sub(elapsed)
            .ok_or(ErrorCode::MathOverflow)?;

        // remaining_pct = remaining * 10000 / total_lock (basis points)
        let remaining_pct = (remaining as u64)
            .checked_mul(10000)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_div(total_lock as u64)
            .ok_or(ErrorCode::MathOverflow)?;

        // Determine penalty tier
        let penalty_bps = if remaining_pct > 5000 {
            PENALTY_TIER_HIGH_BPS // >50% remaining → 50% penalty
        } else if remaining_pct > 2500 {
            PENALTY_TIER_MID_BPS // 25-50% remaining → 30% penalty
        } else {
            PENALTY_TIER_LOW_BPS // <25% remaining → 15% penalty
        };

        let penalty_amount = amount
            .checked_mul(penalty_bps)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_div(10000)
            .ok_or(ErrorCode::MathOverflow)?;

        let user_receives = amount
            .checked_sub(penalty_amount)
            .ok_or(ErrorCode::MathOverflow)?;

        // Settle pending dividends (early unstake = still in lock, use current DPT, no cap)
        let pending = calculate_pending_dividend(
            stake_account.weighted_amount,
            config.dividend_per_token,
            stake_account.last_dividend_per_token,
        )?;
        stake_account.pending_dividends = stake_account
            .pending_dividends
            .checked_add(pending)
            .ok_or(ErrorCode::MathOverflow)?;
        stake_account.last_dividend_per_token = config.dividend_per_token;

        // Proportional weighted removal
        let weighted_removed = (stake_account.weighted_amount as u128)
            .checked_mul(amount as u128)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_div(stake_account.amount as u128)
            .ok_or(ErrorCode::MathOverflow)? as u64;

        let seeds = &[b"config".as_ref(), &[config.bump]];
        let signer_seeds = &[&seeds[..]];

        // Transfer user's portion to user
        if user_receives > 0 {
            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.stake_vault.to_account_info(),
                        to: ctx.accounts.user_zauth.to_account_info(),
                        mint: ctx.accounts.zauth_mint.to_account_info(),
                        authority: ctx.accounts.config.to_account_info(),
                    },
                    signer_seeds,
                ),
                user_receives,
                ZAUTH_DECIMALS,
            )?;
        }

        // Transfer penalty to treasury
        if penalty_amount > 0 {
            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.stake_vault.to_account_info(),
                        to: ctx.accounts.treasury_zauth.to_account_info(),
                        mint: ctx.accounts.zauth_mint.to_account_info(),
                        authority: ctx.accounts.config.to_account_info(),
                    },
                    signer_seeds,
                ),
                penalty_amount,
                ZAUTH_DECIMALS,
            )?;
        }

        stake_account.amount = stake_account
            .amount
            .checked_sub(amount)
            .ok_or(ErrorCode::MathOverflow)?;
        stake_account.weighted_amount = stake_account
            .weighted_amount
            .checked_sub(weighted_removed)
            .ok_or(ErrorCode::MathOverflow)?;

        let config = &mut ctx.accounts.config;
        config.total_staked = config
            .total_staked
            .checked_sub(amount)
            .ok_or(ErrorCode::MathOverflow)?;
        config.total_weighted_staked = config
            .total_weighted_staked
            .checked_sub(weighted_removed)
            .ok_or(ErrorCode::MathOverflow)?;

        Ok(())
    }

    pub fn claim_dividend(ctx: Context<ClaimDividend>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        let stake_account = &mut ctx.accounts.stake_account;

        // Expire weight if lock ended (settles pending at capped DPT, then drops to 0)
        let now = Clock::get()?.unix_timestamp;
        let weight_reduction = expire_weight_if_needed(
            stake_account, config.dividend_per_token,
            config.current_epoch, &config.dpt_snapshots, now,
        )?;
        if weight_reduction > 0 {
            config.total_weighted_staked = config.total_weighted_staked.saturating_sub(weight_reduction);
        }

        // Use epoch-capped DPT
        let effective_dpt = get_effective_dpt(
            stake_account.end_epoch, config.current_epoch,
            config.dividend_per_token, &config.dpt_snapshots,
            stake_account.last_dividend_per_token,
        );

        let new_pending = calculate_pending_dividend(
            stake_account.weighted_amount,
            effective_dpt,
            stake_account.last_dividend_per_token,
        )?;

        let total_claimable = stake_account
            .pending_dividends
            .checked_add(new_pending)
            .ok_or(ErrorCode::MathOverflow)?;

        require!(total_claimable > 0, ErrorCode::NothingToClaim);

        let seeds = &[b"config".as_ref(), &[config.bump]];
        let signer_seeds = &[&seeds[..]];

        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.dividend_vault.to_account_info(),
                    to: ctx.accounts.user_zauth.to_account_info(),
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                signer_seeds,
            ),
            total_claimable,
            ZAUTH_DECIMALS,
        )?;

        stake_account.pending_dividends = 0;
        stake_account.last_dividend_per_token = effective_dpt;

        Ok(())
    }

    /// co-signed emergency withdrawal. both user and admin must sign.
    pub fn rescue_stake(ctx: Context<RescueStake>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);

        let config = &ctx.accounts.config;
        let stake_account = &mut ctx.accounts.stake_account;

        require!(amount <= stake_account.amount, ErrorCode::InsufficientStake);

        // Use epoch-capped DPT for settlement
        let effective_dpt = get_effective_dpt(
            stake_account.end_epoch, config.current_epoch,
            config.dividend_per_token, &config.dpt_snapshots,
            stake_account.last_dividend_per_token,
        );
        let pending = calculate_pending_dividend(
            stake_account.weighted_amount,
            effective_dpt,
            stake_account.last_dividend_per_token,
        )?;
        stake_account.pending_dividends = stake_account
            .pending_dividends
            .checked_add(pending)
            .ok_or(ErrorCode::MathOverflow)?;
        stake_account.last_dividend_per_token = effective_dpt;

        // Proportional weighted removal
        let weighted_removed = if stake_account.weighted_amount > 0 {
            (stake_account.weighted_amount as u128)
                .checked_mul(amount as u128)
                .ok_or(ErrorCode::MathOverflow)?
                .checked_div(stake_account.amount as u128)
                .ok_or(ErrorCode::MathOverflow)? as u64
        } else {
            0
        };

        let seeds = &[b"config".as_ref(), &[config.bump]];
        let signer_seeds = &[&seeds[..]];

        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.stake_vault.to_account_info(),
                    to: ctx.accounts.destination.to_account_info(),
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
            ZAUTH_DECIMALS,
        )?;

        stake_account.amount = stake_account
            .amount
            .checked_sub(amount)
            .ok_or(ErrorCode::MathOverflow)?;
        stake_account.weighted_amount = stake_account
            .weighted_amount
            .checked_sub(weighted_removed)
            .ok_or(ErrorCode::MathOverflow)?;

        let config = &mut ctx.accounts.config;
        config.total_staked = config
            .total_staked
            .checked_sub(amount)
            .ok_or(ErrorCode::MathOverflow)?;
        config.total_weighted_staked = config
            .total_weighted_staked
            .checked_sub(weighted_removed)
            .ok_or(ErrorCode::MathOverflow)?;

        Ok(())
    }

    pub fn close_stake_account(ctx: Context<CloseStakeAccount>) -> Result<()> {
        let stake_account = &ctx.accounts.stake_account;
        require!(stake_account.amount == 0, ErrorCode::StakeNotEmpty);
        require!(
            stake_account.pending_dividends == 0,
            ErrorCode::UnclaimedDividends
        );
        Ok(())
    }

    // --- referrals ---

    pub fn register_referrer(ctx: Context<RegisterReferrer>) -> Result<()> {
        let referral = &mut ctx.accounts.referral_account;
        referral.referrer = ctx.accounts.user.key();
        referral.total_earned = 0;
        referral.pending_payout = 0;
        referral.referral_count = 0;
        referral.bump = ctx.bumps.referral_account;
        Ok(())
    }

    pub fn claim_referral_reward(ctx: Context<ClaimReferralReward>) -> Result<()> {
        let config = &ctx.accounts.config;
        let referral = &mut ctx.accounts.referral_account;

        require!(referral.pending_payout > 0, ErrorCode::NothingToClaim);
        let payout = referral.pending_payout;

        let seeds = &[b"config".as_ref(), &[config.bump]];
        let signer_seeds = &[&seeds[..]];

        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.referral_pool.to_account_info(),
                    to: ctx.accounts.user_zauth.to_account_info(),
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                signer_seeds,
            ),
            payout,
            ZAUTH_DECIMALS,
        )?;

        referral.pending_payout = 0;
        Ok(())
    }

    // --- treasury (admin only) ---

    pub fn deposit_zauth(ctx: Context<DepositZauth>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        token_interface::transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.admin_token.to_account_info(),
                    to: ctx.accounts.treasury_zauth.to_account_info(),
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    authority: ctx.accounts.admin.to_account_info(),
                },
            ),
            amount,
            ZAUTH_DECIMALS,
        )
    }

    /// Withdraw ZAUTH from treasury back to admin wallet.
    pub fn withdraw_zauth(ctx: Context<WithdrawZauth>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        let seeds = &[b"config".as_ref(), &[ctx.accounts.config.bump]];
        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.treasury_zauth.to_account_info(),
                    to: ctx.accounts.admin_token.to_account_info(),
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[seeds],
            ),
            amount,
            ZAUTH_DECIMALS,
        )
    }

    pub fn withdraw_sol(ctx: Context<WithdrawSol>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        let config_info = ctx.accounts.config.to_account_info();
        let admin_info = ctx.accounts.admin.to_account_info();
        let rent = Rent::get()?;
        let min_rent = rent.minimum_balance(config_info.data_len());
        require!(
            config_info
                .lamports()
                .checked_sub(amount)
                .ok_or(ErrorCode::MathOverflow)?
                >= min_rent,
            ErrorCode::InsufficientFunds
        );
        **config_info.try_borrow_mut_lamports()? -= amount;
        **admin_info.try_borrow_mut_lamports()? += amount;
        Ok(())
    }

    pub fn deposit_sol(ctx: Context<DepositSol>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.admin.key(),
            &ctx.accounts.config.key(),
            amount,
        );
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.admin.to_account_info(),
                ctx.accounts.config.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;
        Ok(())
    }

    // --- distributions + burns (admin only) ---

    /// Distribute dividends. `active_weighted` is the sum of weighted_amount for
    /// all stakers whose end_epoch >= current_epoch, computed off-chain by the server.
    /// This excludes expired stakers so no ghost tokens accumulate in the vault.
    pub fn distribute_dividend(ctx: Context<DistributeDividend>, amount: u64, active_weighted: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        require!(active_weighted > 0, ErrorCode::NoStakers);
        let config = &mut ctx.accounts.config;
        // Sanity: active_weighted can't exceed total (would mean more active than exist)
        require!(active_weighted <= config.total_weighted_staked, ErrorCode::InvalidParam);

        let dividend_increase = (amount as u128)
            .checked_mul(PRECISION)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_div(active_weighted as u128)
            .ok_or(ErrorCode::MathOverflow)?;

        config.dividend_per_token = config
            .dividend_per_token
            .checked_add(dividend_increase)
            .ok_or(ErrorCode::MathOverflow)?;
        config.current_epoch = config
            .current_epoch
            .checked_add(1)
            .ok_or(ErrorCode::MathOverflow)?;

        // Snapshot DPT after this distribution into the ring buffer
        let slot = (config.current_epoch % DPT_SNAPSHOT_SLOTS as u64) as usize;
        config.dpt_snapshots[slot] = config.dividend_per_token;

        let seeds = &[b"config".as_ref(), &[config.bump]];
        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.treasury_zauth.to_account_info(),
                    to: ctx.accounts.dividend_vault.to_account_info(),
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[seeds],
            ),
            amount,
            ZAUTH_DECIMALS,
        )
    }

    pub fn burn_tokens(ctx: Context<BurnTokens>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        let seeds = &[b"config".as_ref(), &[ctx.accounts.config.bump]];
        token_interface::burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    from: ctx.accounts.treasury_zauth.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[seeds],
            ),
            amount,
        )
    }

    pub fn fund_referral_pool(ctx: Context<FundReferralPool>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        let seeds = &[b"config".as_ref(), &[ctx.accounts.config.bump]];
        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.treasury_zauth.to_account_info(),
                    to: ctx.accounts.referral_pool.to_account_info(),
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[seeds],
            ),
            amount,
            ZAUTH_DECIMALS,
        )
    }

    /// Sweep tokens from dividend vault back to treasury.
    pub fn sweep_distribution_to_treasury(ctx: Context<SweepToTreasury>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        let seeds = &[b"config".as_ref(), &[ctx.accounts.config.bump]];
        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.source_vault.to_account_info(),
                    to: ctx.accounts.treasury_zauth.to_account_info(),
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[seeds],
            ),
            amount,
            ZAUTH_DECIMALS,
        )
    }

    /// Sweep tokens from referral pool back to treasury.
    pub fn sweep_referral_to_treasury(ctx: Context<SweepReferralToTreasury>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        let seeds = &[b"config".as_ref(), &[ctx.accounts.config.bump]];
        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.source_vault.to_account_info(),
                    to: ctx.accounts.treasury_zauth.to_account_info(),
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[seeds],
            ),
            amount,
            ZAUTH_DECIMALS,
        )
    }

    pub fn allocate_referral_reward(
        ctx: Context<AllocateReferralReward>,
        amount: u64,
    ) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        let referral = &mut ctx.accounts.referral_account;
        referral.pending_payout = referral
            .pending_payout
            .checked_add(amount)
            .ok_or(ErrorCode::MathOverflow)?;
        referral.total_earned = referral
            .total_earned
            .checked_add(amount)
            .ok_or(ErrorCode::MathOverflow)?;
        referral.referral_count = referral
            .referral_count
            .checked_add(1)
            .ok_or(ErrorCode::MathOverflow)?;
        Ok(())
    }

    /// Admin sends referral reward directly from pool to a staker's wallet.
    /// Creates recipient ATA if it doesn't exist. Recipient must have an active stake.
    pub fn distribute_referral_reward(
        ctx: Context<DistributeReferralReward>,
        amount: u64,
    ) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);

        // Verify recipient has an active stake (non-zero amount)
        let stake_account = &ctx.accounts.stake_account;
        require!(stake_account.amount > 0, ErrorCode::InsufficientStake);

        let seeds = &[b"config".as_ref(), &[ctx.accounts.config.bump]];
        let signer_seeds = &[&seeds[..]];

        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.referral_pool.to_account_info(),
                    to: ctx.accounts.recipient_zauth.to_account_info(),
                    mint: ctx.accounts.zauth_mint.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
            ZAUTH_DECIMALS,
        )?;

        Ok(())
    }

    // ================================================================
    // ADMIN: CONFIG
    // ================================================================

    /// can only go down, never up. set to 0 for emergency unlock.
    pub fn update_min_lock(ctx: Context<AdminOnly>, new_min_lock: i64) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(new_min_lock >= 0, ErrorCode::InvalidParam);
        require!(
            new_min_lock < config.min_lock,
            ErrorCode::LockCanOnlyDecrease
        );
        config.min_lock = new_min_lock;
        Ok(())
    }

    pub fn update_max_lock(ctx: Context<AdminOnly>, new_max_lock: i64) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(new_max_lock >= config.min_lock, ErrorCode::InvalidParam);
        config.max_lock = new_max_lock;
        Ok(())
    }

    pub fn update_min_stake(ctx: Context<AdminOnly>, new_min: u64) -> Result<()> {
        ctx.accounts.config.min_stake = new_min;
        Ok(())
    }

    pub fn update_referral_bps(ctx: Context<AdminOnly>, new_bps: u16) -> Result<()> {
        require!(new_bps <= 10000, ErrorCode::InvalidParam);
        ctx.accounts.config.referral_commission_bps = new_bps;
        Ok(())
    }

    pub fn update_epoch_duration(ctx: Context<AdminOnly>, new_duration: i64) -> Result<()> {
        require!(new_duration > 0, ErrorCode::InvalidParam);
        ctx.accounts.config.epoch_duration = new_duration;
        Ok(())
    }

    pub fn update_admin(ctx: Context<AdminOnly>, new_admin: Pubkey) -> Result<()> {
        ctx.accounts.config.pending_admin = new_admin;
        Ok(())
    }

    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(
            ctx.accounts.new_admin.key() == config.pending_admin,
            ErrorCode::Unauthorized
        );
        config.admin = config.pending_admin;
        config.pending_admin = Pubkey::default();
        Ok(())
    }

    // ================================================================
    // ADMIN: EMERGENCY
    // ================================================================

    pub fn pause(
        ctx: Context<AdminOnly>,
        pause_staking: bool,
        pause_unstaking: bool,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.staking_paused = pause_staking;
        config.unstaking_paused = pause_unstaking;
        Ok(())
    }

    pub fn unpause(ctx: Context<AdminOnly>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.staking_paused = false;
        config.unstaking_paused = false;
        Ok(())
    }
}

// ================================================================
// HELPERS
// ================================================================

/// Get the effective DPT for a stake account, capped at end_epoch if expired.
/// end_epoch == 0 means sub-epoch lock (floor division) — earns no distributions.
///
/// SAFETY: the ring buffer has DPT_SNAPSHOT_SLOTS (7) slots. If more than 7
/// epochs pass after end_epoch, the slot at (end_epoch % 7) may have been
/// overwritten by a later distribution, making the snapshot unreliable.
/// In that case we return the user's last_dividend_per_token (passed as
/// `user_dpt`) so pending = 0 — they forfeit the unclaimed delta rather than
/// claiming an inflated amount. Users must claim within 7 epochs of expiry.
/// At production epoch_duration (60 days), that window is 420 days.
fn get_effective_dpt(
    end_epoch: u64,
    current_epoch: u64,
    current_dpt: u128,
    dpt_snapshots: &[u128; DPT_SNAPSHOT_SLOTS],
    user_dpt: u128,
) -> u128 {
    if current_epoch <= end_epoch {
        return current_dpt; // still in lock period, earns current distributions
    }
    // end_epoch == 0 means sub-epoch lock — no distributions earned
    if end_epoch == 0 {
        return user_dpt; // pending = 0
    }
    // Ring buffer staleness check: if the gap is >= ring buffer size,
    // the snapshot slot may have been overwritten by a later epoch.
    // Return user's last DPT to prevent inflated claims.
    if current_epoch - end_epoch >= DPT_SNAPSHOT_SLOTS as u64 {
        return user_dpt;
    }
    // Past end_epoch but within ring buffer range — cap at the snapshot
    let slot = (end_epoch % DPT_SNAPSHOT_SLOTS as u64) as usize;
    let snapshot = dpt_snapshots[slot];
    // If snapshot is 0, the ring buffer slot was never written (e.g. very old epoch).
    // Fall back to current DPT to be generous rather than robbing the user.
    if snapshot > 0 { snapshot } else { current_dpt }
}

/// If lock has expired, settle pending dividends at capped DPT then drop weight to 0.
/// Returns the weight reduction to subtract from global total.
fn expire_weight_if_needed(
    stake_account: &mut StakeAccount,
    config_dpt: u128,
    config_epoch: u64,
    dpt_snapshots: &[u128; DPT_SNAPSHOT_SLOTS],
    now: i64,
) -> Result<u64> {
    if stake_account.amount == 0 || stake_account.weighted_amount == 0 {
        return Ok(0);
    }
    let lock_end = stake_account.staked_at
        .checked_add(stake_account.lock_duration_at_stake)
        .ok_or(ErrorCode::MathOverflow)?;
    if now < lock_end {
        return Ok(0); // still locked, no change
    }
    // Lock expired — settle any pending dividends at capped DPT first
    let effective_dpt = get_effective_dpt(
        stake_account.end_epoch, config_epoch, config_dpt, dpt_snapshots,
        stake_account.last_dividend_per_token,
    );
    let pending = calculate_pending_dividend(
        stake_account.weighted_amount,
        effective_dpt,
        stake_account.last_dividend_per_token,
    )?;
    stake_account.pending_dividends = stake_account
        .pending_dividends
        .checked_add(pending)
        .ok_or(ErrorCode::MathOverflow)?;
    stake_account.last_dividend_per_token = effective_dpt;

    // Drop weight to 0
    let old_weighted = stake_account.weighted_amount;
    stake_account.weighted_amount = 0;
    Ok(old_weighted) // caller subtracts this from total_weighted_staked
}

fn calculate_pending_dividend(weighted_amount: u64, global_dpt: u128, user_dpt: u128) -> Result<u64> {
    if weighted_amount == 0 || global_dpt <= user_dpt {
        return Ok(0);
    }
    let diff = global_dpt
        .checked_sub(user_dpt)
        .ok_or(ErrorCode::MathOverflow)?;
    let pending = (weighted_amount as u128)
        .checked_mul(diff)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(PRECISION)
        .ok_or(ErrorCode::MathOverflow)?;
    Ok(pending as u64)
}

/// Returns weight in basis points for a given lock duration.
/// 30d → 10000 (1x), 365d → 20000 (2x), linear between, clamped at ends.
fn calculate_weight_bps(lock_duration: i64) -> Result<u64> {
    if lock_duration <= WEIGHT_MIN_LOCK {
        return Ok(WEIGHT_BASE_BPS);
    }
    if lock_duration >= WEIGHT_MAX_LOCK {
        return Ok(WEIGHT_MAX_BPS);
    }
    let bonus = ((WEIGHT_MAX_BPS - WEIGHT_BASE_BPS) as u128)
        .checked_mul((lock_duration - WEIGHT_MIN_LOCK) as u128)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div((WEIGHT_MAX_LOCK - WEIGHT_MIN_LOCK) as u128)
        .ok_or(ErrorCode::MathOverflow)?;
    Ok(WEIGHT_BASE_BPS + bonus as u64)
}

/// Compute weighted amount: amount * weight_bps / WEIGHT_BASE_BPS
fn compute_weighted_amount(amount: u64, weight_bps: u64) -> Result<u64> {
    let result = (amount as u128)
        .checked_mul(weight_bps as u128)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(WEIGHT_BASE_BPS as u128)
        .ok_or(ErrorCode::MathOverflow)?;
    Ok(result as u64)
}

// ================================================================
// ACCOUNT STRUCTURES
// ================================================================

#[account]
pub struct TreasuryConfig {
    pub admin: Pubkey,          // 32
    pub pending_admin: Pubkey,  // 32
    pub zauth_mint: Pubkey,     // 32
    pub stake_vault: Pubkey,    // 32
    pub treasury_zauth: Pubkey, // 32
    pub dividend_vault: Pubkey, // 32
    pub referral_pool: Pubkey,  // 32

    pub total_staked: u64,          // 8  (raw token count)
    pub total_weighted_staked: u64, // 8  (lock-weighted total for dividend math)
    pub dividend_per_token: u128,   // 16
    pub current_epoch: u64,         // 8

    pub min_lock: i64,                   // 8  (minimum lock duration in seconds)
    pub max_lock: i64,                   // 8  (maximum lock duration in seconds)
    pub min_stake: u64,                  // 8
    pub referral_commission_bps: u16,    // 2

    pub staking_paused: bool,   // 1
    pub unstaking_paused: bool, // 1
    pub init_phase: u8,         // 1

    pub bump: u8,                // 1
    pub stake_vault_bump: u8,    // 1
    pub treasury_zauth_bump: u8, // 1
    pub dividend_vault_bump: u8, // 1
    pub referral_pool_bump: u8,  // 1

    // --- epoch dividend cap fields ---
    pub epoch_duration: i64,                            // 8  (seconds per epoch, e.g. 5184000 = 60 days)
    pub dpt_snapshots: [u128; DPT_SNAPSHOT_SLOTS],      // 112 (DPT after each distribution, ring buffer)
}

#[account]
pub struct StakeAccount {
    pub owner: Pubkey,                 // 32
    pub amount: u64,                   // 8  (raw staked tokens)
    pub staked_at: i64,                // 8
    pub lock_duration_at_stake: i64,   // 8  (user-chosen lock in seconds)
    pub last_dividend_per_token: u128, // 16
    pub pending_dividends: u64,        // 8
    pub bump: u8,                      // 1
    pub weighted_amount: u64,          // 8  (amount * lock weight multiplier)

    // --- epoch cap field ---
    pub end_epoch: u64,                // 8  (last epoch this stake earns from, inclusive)
}

#[account]
pub struct ReferralAccount {
    pub referrer: Pubkey,    // 32
    pub total_earned: u64,   // 8
    pub pending_payout: u64, // 8
    pub referral_count: u32, // 4
    pub bump: u8,            // 1
}

// ================================================================
// ACCOUNT CONTEXTS
// ================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(init, payer = admin, space = 8 + std::mem::size_of::<TreasuryConfig>() + CONFIG_PADDING, seeds = [b"config"], bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    #[account(init, payer = admin, token::mint = zauth_mint, token::authority = config, seeds = [b"stake_vault"], bump)]
    pub stake_vault: InterfaceAccount<'info, TokenAccount>,
    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(vault_type: u8)]
pub struct RegisterVault<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(init, payer = admin, token::mint = mint, token::authority = config, seeds = [b"v", &[vault_type]], bump)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    pub mint: InterfaceAccount<'info, Mint>,
    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct StakeTokens<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(init_if_needed, payer = user, space = 8 + std::mem::size_of::<StakeAccount>() + STAKE_PADDING, seeds = [b"stake", user.key().as_ref()], bump)]
    pub stake_account: Account<'info, StakeAccount>,
    #[account(mut, constraint = stake_vault.key() == config.stake_vault @ ErrorCode::InvalidVault)]
    pub stake_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = user_zauth.owner == user.key() @ ErrorCode::Unauthorized, constraint = user_zauth.mint == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub user_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Unstake<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut, seeds = [b"stake", user.key().as_ref()], bump = stake_account.bump, constraint = stake_account.owner == user.key() @ ErrorCode::Unauthorized)]
    pub stake_account: Account<'info, StakeAccount>,
    #[account(mut, constraint = stake_vault.key() == config.stake_vault @ ErrorCode::InvalidVault)]
    pub stake_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = user_zauth.owner == user.key() @ ErrorCode::Unauthorized, constraint = user_zauth.mint == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub user_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct EarlyUnstake<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut, seeds = [b"stake", user.key().as_ref()], bump = stake_account.bump, constraint = stake_account.owner == user.key() @ ErrorCode::Unauthorized)]
    pub stake_account: Account<'info, StakeAccount>,
    #[account(mut, constraint = stake_vault.key() == config.stake_vault @ ErrorCode::InvalidVault)]
    pub stake_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = user_zauth.owner == user.key() @ ErrorCode::Unauthorized, constraint = user_zauth.mint == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub user_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = treasury_zauth.key() == config.treasury_zauth @ ErrorCode::InvalidVault)]
    pub treasury_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ClaimDividend<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut, seeds = [b"stake", user.key().as_ref()], bump = stake_account.bump, constraint = stake_account.owner == user.key() @ ErrorCode::Unauthorized)]
    pub stake_account: Account<'info, StakeAccount>,
    #[account(mut, constraint = dividend_vault.key() == config.dividend_vault @ ErrorCode::InvalidVault)]
    pub dividend_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = user_zauth.owner == user.key() @ ErrorCode::Unauthorized, constraint = user_zauth.mint == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub user_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct RescueStake<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut, seeds = [b"stake", user.key().as_ref()], bump = stake_account.bump, constraint = stake_account.owner == user.key() @ ErrorCode::Unauthorized)]
    pub stake_account: Account<'info, StakeAccount>,
    #[account(mut, constraint = stake_vault.key() == config.stake_vault @ ErrorCode::InvalidVault)]
    pub stake_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = destination.mint == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub destination: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CloseStakeAccount<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"stake", user.key().as_ref()], bump = stake_account.bump, constraint = stake_account.owner == user.key() @ ErrorCode::Unauthorized, close = user)]
    pub stake_account: Account<'info, StakeAccount>,
}

#[derive(Accounts)]
pub struct RegisterReferrer<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(init, payer = user, space = 8 + std::mem::size_of::<ReferralAccount>() + REFERRAL_PADDING, seeds = [b"referral", user.key().as_ref()], bump)]
    pub referral_account: Account<'info, ReferralAccount>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimReferralReward<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut, seeds = [b"referral", user.key().as_ref()], bump = referral_account.bump, constraint = referral_account.referrer == user.key() @ ErrorCode::Unauthorized)]
    pub referral_account: Account<'info, ReferralAccount>,
    #[account(mut, constraint = referral_pool.key() == config.referral_pool @ ErrorCode::InvalidVault)]
    pub referral_pool: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = user_zauth.owner == user.key() @ ErrorCode::Unauthorized, constraint = user_zauth.mint == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub user_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct DepositZauth<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut, constraint = admin_token.owner == admin.key() @ ErrorCode::Unauthorized, constraint = admin_token.mint == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub admin_token: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = treasury_zauth.key() == config.treasury_zauth @ ErrorCode::InvalidVault)]
    pub treasury_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct WithdrawZauth<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut, constraint = admin_token.owner == admin.key() @ ErrorCode::Unauthorized, constraint = admin_token.mint == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub admin_token: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = treasury_zauth.key() == config.treasury_zauth @ ErrorCode::InvalidVault)]
    pub treasury_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct WithdrawSol<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
}

#[derive(Accounts)]
pub struct DepositSol<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DistributeDividend<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut, constraint = treasury_zauth.key() == config.treasury_zauth @ ErrorCode::InvalidVault)]
    pub treasury_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = dividend_vault.key() == config.dividend_vault @ ErrorCode::InvalidVault)]
    pub dividend_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct BurnTokens<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut, constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    #[account(mut, constraint = treasury_zauth.key() == config.treasury_zauth @ ErrorCode::InvalidVault)]
    pub treasury_zauth: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct FundReferralPool<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut, constraint = treasury_zauth.key() == config.treasury_zauth @ ErrorCode::InvalidVault)]
    pub treasury_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = referral_pool.key() == config.referral_pool @ ErrorCode::InvalidVault)]
    pub referral_pool: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct SweepToTreasury<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut, constraint = source_vault.key() == config.dividend_vault @ ErrorCode::InvalidVault)]
    pub source_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = treasury_zauth.key() == config.treasury_zauth @ ErrorCode::InvalidVault)]
    pub treasury_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct SweepReferralToTreasury<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut, constraint = source_vault.key() == config.referral_pool @ ErrorCode::InvalidVault)]
    pub source_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, constraint = treasury_zauth.key() == config.treasury_zauth @ ErrorCode::InvalidVault)]
    pub treasury_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct AllocateReferralReward<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    #[account(mut)]
    pub referral_account: Account<'info, ReferralAccount>,
}

#[derive(Accounts)]
pub struct DistributeReferralReward<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
    /// CHECK: recipient wallet address, validated via stake_account constraint
    pub recipient: AccountInfo<'info>,
    #[account(
        seeds = [b"stake", recipient.key().as_ref()],
        bump = stake_account.bump,
        constraint = stake_account.owner == recipient.key() @ ErrorCode::Unauthorized,
    )]
    pub stake_account: Account<'info, StakeAccount>,
    #[account(mut, constraint = referral_pool.key() == config.referral_pool @ ErrorCode::InvalidVault)]
    pub referral_pool: InterfaceAccount<'info, TokenAccount>,
    #[account(
        init_if_needed,
        payer = admin,
        associated_token::mint = zauth_mint,
        associated_token::authority = recipient,
        associated_token::token_program = token_program,
    )]
    pub recipient_zauth: InterfaceAccount<'info, TokenAccount>,
    #[account(constraint = zauth_mint.key() == config.zauth_mint @ ErrorCode::InvalidMint)]
    pub zauth_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(mut, constraint = admin.key() == config.admin @ ErrorCode::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    #[account(mut)]
    pub new_admin: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, TreasuryConfig>>,
}

// ================================================================
// ERRORS
// ================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Amount must be greater than zero")]
    ZeroAmount,
    #[msg("Below minimum stake amount")]
    BelowMinStake,
    #[msg("Staking is paused")]
    StakingPaused,
    #[msg("Unstaking is paused")]
    UnstakingPaused,
    #[msg("Tokens are still locked")]
    StillLocked,
    #[msg("Lock has already expired — use normal unstake")]
    LockAlreadyExpired,
    #[msg("Insufficient staked balance")]
    InsufficientStake,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Nothing to claim")]
    NothingToClaim,
    #[msg("Math overflow")]
    MathOverflow,
    #[msg("No stakers to distribute to")]
    NoStakers,
    #[msg("Lock duration can only decrease")]
    LockCanOnlyDecrease,
    #[msg("Invalid parameter")]
    InvalidParam,
    #[msg("Invalid vault account")]
    InvalidVault,
    #[msg("Invalid mint")]
    InvalidMint,
    #[msg("Stake account still has tokens")]
    StakeNotEmpty,
    #[msg("Unclaimed dividends remain")]
    UnclaimedDividends,
    #[msg("Already initialized")]
    AlreadyInitialized,
    #[msg("Invalid initialization phase")]
    InvalidInitPhase,
    #[msg("Lock duration below minimum")]
    LockTooShort,
    #[msg("Lock duration above maximum")]
    LockTooLong,
    #[msg("New lock must be >= remaining lock duration")]
    LockShorterThanRemaining,
}
