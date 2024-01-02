use anchor_lang::prelude::*;
use anchor_spl::token::{self, MintTo, Transfer};
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

declare_id!("5e2TUn4NnhCWkoCFHZJXPPtpEHW1fz7T1S9FtPqo7yxq");

#[program]
pub mod solana_drop_blog {
    use super::*;

    #[error_code]
    pub enum ErrorCode {
        NotEligible,
        DropEnded,
    }

    pub fn initialize(
        ctx: Context<Initialize>,
        start_time: u64,
        end_time: u64,
        amount_claim: u64,
    ) -> Result<()> {
        msg!("Instruction: Initialize");

        let pool_info = &mut ctx.accounts.pool_info;

        pool_info.admin = ctx.accounts.admin.key();
        pool_info.start_time = start_time;
        pool_info.end_time = end_time;
        pool_info.amount_claim = amount_claim;
        pool_info.token = ctx.accounts.airdrop_token.key();

        Ok(())
    }

    pub fn add_items(ctx: Context<AddItem>, users_to_add: Vec<Pubkey>) -> Result<()> {
        let white_list_info = &mut ctx.accounts.white_list_info;
        require!(ctx.accounts.admin.key() == ctx.accounts.pool_info.admin, ErrorCode::NotEligible);
        white_list_info.items.extend(users_to_add);
        Ok(())
    }

    pub fn remove_item(ctx: Context<RemoveItem>, user: Pubkey) -> Result<()> {
        let white_list_info = &mut ctx.accounts.white_list_info;
        require!(ctx.accounts.admin.key() == ctx.accounts.pool_info.admin, ErrorCode::NotEligible);
        if let Some(index) = white_list_info.items.iter().position(|&x| x == user) {
            white_list_info.items.remove(index);
        }
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        msg!("Instruction: Deposit");
    
        let pool_info = &mut ctx.accounts.pool_info;
        require!(ctx.accounts.user.key() == pool_info.admin, ErrorCode::NotEligible);

        let cpi_accounts = Transfer {
            from: ctx.accounts.user_wallet.to_account_info(),
            to: ctx.accounts.admin_drop_wallet.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        pool_info.total_deposit += amount;

        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        msg!("Instruction: Withdraw");

        let pool_info = &mut ctx.accounts.pool_info;
        let clock = Clock::get()?;

        if (pool_info.total_deposit > pool_info.total_claim) && (pool_info.end_time > clock.unix_timestamp.try_into().unwrap()) {
            let cpi_accounts = Transfer {
                from: ctx.accounts.admin_drop_wallet.to_account_info(),
                to: ctx.accounts.admin.to_account_info(),
                authority: ctx.accounts.admin.to_account_info(),
            };
            let cpi_program = ctx.accounts.token_program.to_account_info();
            let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
            token::transfer(cpi_ctx, pool_info.total_deposit - pool_info.total_claim)?;
            pool_info.total_claim = pool_info.total_deposit;
        }

        Ok(())
    }

    pub fn claim_reward(ctx: Context<ClaimReward>) -> Result<()> {
        msg!("Instruction: Claim Reward");
        if !is_whitelisted(ctx.accounts.white_list.items, ctx.accounts.user.key()) {
            return Err(ErrorCode::NotEligible.into());
        }

        let pool_info = &mut ctx.accounts.pool_info;
        let clock = Clock::get()?;

        if pool_info.end_time > clock.unix_timestamp.try_into().unwrap() {
            return Err(ErrorCode::DropEnded.into());
        }

        let cpi_accounts = Transfer {
            from: ctx.accounts.admin_drop_wallet.to_account_info(),
            to: ctx.accounts.user_wallet.to_account_info(),
            authority: ctx.accounts.admin.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, pool_info.amount_claim)?;

        pool_info.total_claim += pool_info.amount_claim;

        Ok(())
    }
    
    pub fn is_whitelisted(items: Vec<Pubkey>, user_address: Pubkey) -> bool {
        return items.iter().any(|item| *item == user_address);
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(init, payer = admin, space = 8 + PoolInfo::LEN)]
    pub pool_info: Account<'info, PoolInfo>,
    #[account(mut)]
    pub airdrop_token: InterfaceAccount<'info, Mint>,
    #[account(mut)]
    pub admin_drop_wallet: InterfaceAccount<'info, TokenAccount>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut)]
    pub pool_info: Account<'info, PoolInfo>,
    #[account(mut)]
    pub user_wallet: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub admin_drop_wallet: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK:
    #[account(mut)]
    pub user: AccountInfo<'info>,
    /// CHECK:
    #[account(mut)]
    pub admin: AccountInfo<'info>,
    #[account(mut)]
    pub pool_info: Account<'info, PoolInfo>,
    #[account(mut)]
    pub user_wallet: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub admin_drop_wallet: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimReward<'info> {
    /// CHECK:
    #[account(mut)]
    pub user: AccountInfo<'info>,
    /// CHECK:
    #[account(mut)]
    pub admin: AccountInfo<'info>,
    #[account(mut)]
    pub user_wallet: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub admin_drop_wallet: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub pool_info: Account<'info, PoolInfo>,
    #[account(mut)]
    pub white_list: Account<'info, WhiteListInfo>,
    #[account(mut)]
    pub airdrop_token: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct AddItem<'info> {
    #[account(mut)]
    pub white_list_info: Account<'info, WhiteListInfo>,
    #[account(signer)]
    pub admin: AccountInfo<'info>,
    #[account(mut)]
    pub pool_info: Account<'info, PoolInfo>,
}

#[derive(Accounts)]
pub struct RemoveItem<'info> {
    #[account(mut)]
    pub white_list_info: Account<'info, WhiteListInfo>,
    #[account(signer)]
    pub admin: AccountInfo<'info>,
    #[account(mut)]
    pub pool_info: Account<'info, PoolInfo>,
}

#[account]
pub struct PoolInfo {
    pub admin: Pubkey,
    pub start_time: u64,
    pub end_time: u64,
    pub token: Pubkey,
    pub amount_claim: u64,
    pub total_deposit: u64,
    pub total_claim: u64,
}

#[account]
pub struct WhiteListInfo {
    pub items: Vec<Pubkey>,
}

impl PoolInfo {
    pub const LEN: usize = 32 + 8 + 8 + 32 + 8 + 8 + 8;
}
