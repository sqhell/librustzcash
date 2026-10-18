//! Implementation of the synchronization flow described in the crate root.
//!
//! This is currently a simple implementation that does not yet implement a few features:
//!
//! - Block batches are not downloaded in parallel with scanning.
//! - Transactions are not enhanced once detected (that is, after an output is detected in
//!   a transaction, the full transaction is not downloaded and scanned).
//! - There is no mechanism for notifying the caller of progress updates.
//! - There is no mechanism for interrupting the synchronization flow from within [`run`],
//!   other than ending the process. Callers that need to pause, persist, or stop between
//!   batches can drive the same flow one bounded step at a time with [`run_step`].

#[cfg(feature = "sync")]
use {
    crate::{
        data_api::{
            WalletCommitmentTrees, WalletRead, WalletWrite,
            chain::{
                BlockCache, ChainState, CommitmentTreeRoot, error::Error as ChainError,
                scan_cached_blocks,
            },
            scanning::{ScanPriority, ScanRange},
        },
        proto::service::{self, BlockId, compact_tx_streamer_client::CompactTxStreamerClient},
        scanning::ScanError,
    },
    futures_util::TryStreamExt,
    shardtree::error::ShardTreeError,
    std::{fmt, future::Future},
    subtle::ConditionallySelectable,
    tonic::{
        body::Body as TonicBody,
        client::GrpcService,
        codegen::{Body, Bytes, StdError},
    },
    tracing::{debug, info},
    zcash_primitives::merkle_tree::HashSer,
    zcash_protocol::consensus::{BlockHeight, Parameters},
};

#[cfg(all(feature = "sync", feature = "orchard"))]
use orchard::tree::MerkleHashOrchard;

#[cfg(all(feature = "sync", feature = "transparent-inputs"))]
use {
    crate::wallet::WalletTransparentOutput,
    ::transparent::{
        address::Script,
        bundle::{OutPoint, TxOut},
    },
    zcash_keys::encoding::AddressCodec as _,
    zcash_protocol::value::Zatoshis,
    zcash_script::script,
};

#[cfg(feature = "sync-decryptor")]
pub mod decryptor;

/// Scans the chain until the wallet is up-to-date.
#[cfg(feature = "sync")]
pub async fn run<P, ChT, CaT, DbT>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    db_cache: &CaT,
    db_data: &mut DbT,
    batch_size: u32,
) -> Result<(), Error<CaT::Error, <DbT as WalletRead>::Error, <DbT as WalletCommitmentTrees>::Error>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite + WalletCommitmentTrees,
    DbT::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
    <DbT as WalletRead>::Error: std::error::Error + Send + Sync + 'static,
    <DbT as WalletCommitmentTrees>::Error: std::error::Error + Send + Sync + 'static,
{
    // 1) Download note commitment tree data from lightwalletd
    // 2) Pass the commitment tree data to the database.
    update_subtree_roots(client, db_data).await?;

    let opts = StepOptions {
        refresh_subtree_roots: false,
        max_batches: usize::MAX,
    };
    while run_step(client, params, db_cache, db_data, batch_size, opts).await? {}

    Ok(())
}

/// Options for [`run_step`].
#[cfg(feature = "sync")]
#[derive(Clone, Copy, Debug)]
pub struct StepOptions {
    /// Refresh the subtree roots from the server before scanning. Needed on the first step of a
    /// sync and after a long pause; skipping it on later steps saves a network round trip.
    pub refresh_subtree_roots: bool,
    /// Scan at most this many batches before returning. `usize::MAX` behaves like [`run`].
    ///
    /// A step that has work to do always scans at least one batch, so a value of `0` is
    /// treated as `1`.
    pub max_batches: usize,
}

/// Performs a bounded amount of sync work and reports whether more remains.
///
/// Equivalent to [`run`] when called repeatedly until it returns `Ok(false)`, but returns after
/// at most `opts.max_batches` scanned batches so the caller can release locks, persist the
/// wallet, or stop. Each return point leaves the wallet in a state a later call (or a later
/// process) can resume from: ranges not yet scanned stay in the scan queue, and cached blocks
/// already scanned have been deleted.
///
/// Every call refreshes the wallet's view of the chain tip (and, with the `transparent-inputs`
/// feature, its UTXOs) before scanning, so a step that finds no work left returns `Ok(false)`
/// without scanning anything.
///
/// Returns `Ok(true)` if the caller should call this function again, either because the batch
/// budget was exhausted or because scanning changed the suggested scan ranges, and `Ok(false)`
/// once the wallet reports no further ranges to scan.
///
/// # Errors
///
/// Returns the same errors as [`run`]: a failure while talking to the server
/// ([`Error::Server`], [`Error::MisbehavingServer`]), while reading or writing the block cache
/// ([`Error::Cache`]), while scanning ([`Error::Scan`]), or while reading or writing the wallet
/// ([`Error::Wallet`], [`Error::WalletTrees`]).
#[cfg(feature = "sync")]
pub async fn run_step<P, ChT, CaT, DbT>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    db_cache: &CaT,
    db_data: &mut DbT,
    batch_size: u32,
    opts: StepOptions,
) -> Result<
    bool,
    Error<CaT::Error, <DbT as WalletRead>::Error, <DbT as WalletCommitmentTrees>::Error>,
>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite + WalletCommitmentTrees,
    DbT::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
    <DbT as WalletRead>::Error: std::error::Error + Send + Sync + 'static,
    <DbT as WalletCommitmentTrees>::Error: std::error::Error + Send + Sync + 'static,
{
    if opts.refresh_subtree_roots {
        update_subtree_roots(client, db_data).await?;
    }

    running(
        client,
        params,
        db_cache,
        db_data,
        batch_size,
        BatchBudget::new(opts.max_batches),
    )
    .await
}

/// The number of batches a single call to [`running`] may still scan.
#[cfg(feature = "sync")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BatchBudget {
    remaining: usize,
}

/// Whether a [`BatchBudget`] permits scanning further batches.
#[cfg(feature = "sync")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BudgetState {
    /// At least one more batch may be scanned.
    Remaining,
    /// No further batches may be scanned in this step.
    Exhausted,
}

#[cfg(feature = "sync")]
impl BatchBudget {
    /// Constructs a budget permitting at most `max_batches` batches, with a minimum of one so
    /// that a step always makes progress when work remains.
    fn new(max_batches: usize) -> Self {
        Self {
            remaining: max_batches.max(1),
        }
    }

    /// Records that one batch has been scanned and reports whether the budget now permits
    /// scanning another.
    fn record_batch(&mut self) -> BudgetState {
        self.remaining = self.remaining.saturating_sub(1);
        if self.remaining == 0 {
            BudgetState::Exhausted
        } else {
            BudgetState::Remaining
        }
    }
}

/// Waits for the given cached-block deletions to complete.
#[cfg(feature = "sync")]
async fn await_block_deletions<CaErr, DbErr, TrErr>(
    block_deletions: Vec<impl Future<Output = Result<(), CaErr>>>,
) -> Result<(), Error<CaErr, DbErr, TrErr>> {
    info!("Waiting for cached blocks to be deleted...");
    for deletion in block_deletions {
        deletion.await.map_err(Error::Cache)?;
    }
    Ok(())
}

/// Performs one step of the sync flow, scanning at most `budget` batches.
///
/// Returns `Ok(true)` if the caller should call this function again (either because the
/// suggested scan ranges were updated or because the batch budget was exhausted), and
/// `Ok(false)` once the wallet reports no further ranges to scan.
#[cfg(feature = "sync")]
async fn running<P, ChT, CaT, DbT, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    db_cache: &CaT,
    db_data: &mut DbT,
    batch_size: u32,
    mut budget: BatchBudget,
) -> Result<bool, Error<CaT::Error, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite,
    DbT::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    // 3) Download chain tip metadata from lightwalletd
    // 4) Notify the wallet of the updated chain tip.
    update_chain_tip(client, db_data).await?;

    // Refresh UTXOs for the accounts in the wallet. We do this before we perform
    // any shielded scanning, to ensure that we discover any UTXOs between the old
    // fully-scanned height and the current chain tip.
    #[cfg(feature = "transparent-inputs")]
    for account_id in db_data.get_account_ids().map_err(Error::Wallet)? {
        let start_height = db_data
            .utxo_query_height(account_id)
            .map_err(Error::Wallet)?;
        info!(
            "Refreshing UTXOs for {:?} from height {}",
            account_id, start_height,
        );
        refresh_utxos(params, client, db_data, account_id, start_height).await?;
    }

    // 5) Get the suggested scan ranges from the wallet database
    let mut scan_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;

    // Store the handles to cached block deletions (which we spawn into separate
    // tasks to allow us to continue downloading and scanning other ranges).
    let mut block_deletions = vec![];

    // 6) Run the following loop until the wallet's view of the chain tip as of
    //    the previous wallet session is valid.
    loop {
        // If there is a range of blocks that needs to be verified, it will always
        // be returned as the first element of the vector of suggested ranges.
        match scan_ranges.first() {
            Some(scan_range) if scan_range.priority() == ScanPriority::Verify => {
                // Download the blocks in `scan_range` into the block source,
                // overwriting any existing blocks in this range.
                download_blocks(client, db_cache, scan_range).await?;

                let chain_state =
                    download_chain_state(client, scan_range.block_range().start - 1).await?;

                // Scan the downloaded blocks and check for scanning errors that
                // indicate the wallet's chain tip is out of sync with blockchain
                // history.
                let scan_ranges_updated =
                    scan_blocks(params, db_cache, db_data, &chain_state, scan_range).await?;

                // Delete the now-scanned blocks, because keeping the entire chain
                // in CompactBlock files on disk is horrendous for the filesystem.
                block_deletions.push(db_cache.delete(scan_range.clone()));

                if budget.record_batch() == BudgetState::Exhausted {
                    // The caller asked us to stop here. The verified range has been
                    // scanned and removed from the scan queue, so the next step will
                    // pick up whatever remains.
                    await_block_deletions(block_deletions).await?;
                    return Ok(true);
                }

                if scan_ranges_updated {
                    // The suggested scan ranges have been updated, so we re-request.
                    scan_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;
                } else {
                    // At this point, the cache and scanned data are locally
                    // consistent (though not necessarily consistent with the
                    // latest chain tip - this would be discovered the next time
                    // this codepath is executed after new blocks are received) so
                    // we can break out of the loop.
                    break;
                }
            }
            _ => {
                // Nothing to verify; break out of the loop
                break;
            }
        }
    }

    // 7) Loop over the remaining suggested scan ranges, retrieving the requested data
    //    and calling `scan_cached_blocks` on each range.
    let scan_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;
    debug!("Suggested ranges: {:?}", scan_ranges);
    for scan_range in scan_ranges.into_iter().flat_map(|r| {
        // Limit the number of blocks we download and scan at any one time.
        (0..).scan(r, |acc, _| {
            if acc.is_empty() {
                None
            } else if let Some((cur, next)) = acc.split_at(acc.block_range().start + batch_size) {
                *acc = next;
                Some(cur)
            } else {
                let cur = acc.clone();
                let end = acc.block_range().end;
                *acc = ScanRange::from_parts(end..end, acc.priority());
                Some(cur)
            }
        })
    }) {
        // Download the blocks in `scan_range` into the block source.
        download_blocks(client, db_cache, &scan_range).await?;

        let chain_state = download_chain_state(client, scan_range.block_range().start - 1).await?;

        // Scan the downloaded blocks.
        let scan_ranges_updated =
            scan_blocks(params, db_cache, db_data, &chain_state, &scan_range).await?;

        // Delete the now-scanned blocks.
        block_deletions.push(db_cache.delete(scan_range));

        let budget_exhausted = budget.record_batch() == BudgetState::Exhausted;

        if scan_ranges_updated || budget_exhausted {
            // Either the suggested scan ranges have been updated (due to a continuity
            // error or because a higher priority range has been added), or the caller
            // asked us to stop after this many batches. In both cases the ranges that
            // remain are still in the scan queue, so the next step resumes from here.
            await_block_deletions(block_deletions).await?;
            return Ok(true);
        }
    }

    await_block_deletions(block_deletions).await?;
    Ok(false)
}

#[cfg(feature = "sync")]
async fn download_subtree_roots<ChT, H>(
    client: &mut CompactTxStreamerClient<ChT>,
    protocol: service::ShieldedProtocol,
) -> Result<Vec<CommitmentTreeRoot<H>>, tonic::Status>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    H: HashSer,
{
    let mut request = service::GetSubtreeRootsArg::default();
    request.set_shielded_protocol(protocol);

    client
        .get_subtree_roots(request)
        .await?
        .into_inner()
        .and_then(|root| async move {
            let root_hash = H::read(&root.root_hash[..])?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_block_height as u32),
                root_hash,
            ))
        })
        .try_collect()
        .await
}

#[cfg(feature = "sync")]
async fn update_subtree_roots<ChT, DbT, CaErr, DbErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    db_data: &mut DbT,
) -> Result<(), Error<CaErr, DbErr, <DbT as WalletCommitmentTrees>::Error>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletCommitmentTrees,
    <DbT as WalletCommitmentTrees>::Error: std::error::Error + Send + Sync + 'static,
{
    let sapling_roots: Vec<CommitmentTreeRoot<sapling::Node>> =
        download_subtree_roots(client, service::ShieldedProtocol::Sapling).await?;

    info!("Sapling tree has {} subtrees", sapling_roots.len());
    db_data
        .put_sapling_subtree_roots(0, &sapling_roots)
        .map_err(Error::WalletTrees)?;

    #[cfg(feature = "orchard")]
    {
        let orchard_roots: Vec<CommitmentTreeRoot<MerkleHashOrchard>> =
            download_subtree_roots(client, service::ShieldedProtocol::Orchard).await?;

        info!("Orchard tree has {} subtrees", orchard_roots.len());
        db_data
            .put_orchard_subtree_roots(0, &orchard_roots)
            .map_err(Error::WalletTrees)?;

        let ironwood_roots: Vec<CommitmentTreeRoot<MerkleHashOrchard>> =
            download_subtree_roots(client, service::ShieldedProtocol::Ironwood).await?;

        info!("Ironwood tree has {} subtrees", ironwood_roots.len());
        db_data
            .put_ironwood_subtree_roots(0, &ironwood_roots)
            .map_err(Error::WalletTrees)?;
    }

    Ok(())
}

#[cfg(feature = "sync")]
async fn update_chain_tip<ChT, DbT, CaErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    db_data: &mut DbT,
) -> Result<(), Error<CaErr, <DbT as WalletRead>::Error, TrErr>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletWrite,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let tip_height: BlockHeight = client
        .get_latest_block(service::ChainSpec::default())
        .await?
        .get_ref()
        .height
        .try_into()
        .map_err(|_| Error::MisbehavingServer)?;

    info!("Latest block height is {}", tip_height);
    db_data
        .update_chain_tip(tip_height)
        .map_err(Error::Wallet)?;

    Ok(())
}

#[cfg(feature = "sync")]
async fn download_blocks<ChT, CaT, DbErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    db_cache: &CaT,
    scan_range: &ScanRange,
) -> Result<(), Error<CaT::Error, DbErr, TrErr>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
{
    info!("Fetching {}", scan_range);
    let mut start = service::BlockId::default();
    start.height = scan_range.block_range().start.into();
    let mut end = service::BlockId::default();
    end.height = (scan_range.block_range().end - 1).into();
    let range = service::BlockRange {
        start: Some(start),
        end: Some(end),
        pool_types: vec![],
    };
    let compact_blocks = client
        .get_block_range(range)
        .await?
        .into_inner()
        .try_collect::<Vec<_>>()
        .await?;

    db_cache
        .insert(compact_blocks)
        .await
        .map_err(Error::Cache)?;

    Ok(())
}

#[cfg(feature = "sync")]
async fn download_chain_state<ChT, CaErr, DbErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    block_height: BlockHeight,
) -> Result<ChainState, Error<CaErr, DbErr, TrErr>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    let tree_state = client
        .get_tree_state(BlockId {
            height: block_height.into(),
            hash: vec![],
        })
        .await?;

    tree_state
        .into_inner()
        .to_chain_state()
        .map_err(|_| Error::MisbehavingServer)
}

/// Scans the given block range and checks for scanning errors that indicate the wallet's
/// chain tip is out of sync with blockchain history.
///
/// Returns `true` if scanning these blocks materially changed the suggested scan ranges.
#[cfg(feature = "sync")]
async fn scan_blocks<P, CaT, DbT, TrErr>(
    params: &P,
    db_cache: &CaT,
    db_data: &mut DbT,
    initial_chain_state: &ChainState,
    scan_range: &ScanRange,
) -> Result<bool, Error<CaT::Error, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite,
    DbT::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    info!("Scanning {}", scan_range);
    let scan_result = scan_cached_blocks(
        params,
        db_cache,
        db_data,
        scan_range.block_range().start,
        initial_chain_state,
        scan_range.len(),
    );

    match scan_result {
        Err(ChainError::Scan(err)) if err.is_continuity_error() => {
            // Pick a height to rewind to, which must be at least one block before the
            // height at which the error occurred, but may be an earlier height determined
            // based on heuristics such as the platform, available bandwidth, size of
            // recent CompactBlocks, etc.
            let rewind_height = err.at_height().saturating_sub(10);
            info!(
                "Chain reorg detected at {}, rewinding to {}",
                err.at_height(),
                rewind_height,
            );

            // Rewind to the chosen height.
            db_data
                .truncate_to_height(rewind_height)
                .map_err(Error::Wallet)?;

            // Delete cached blocks from rewind_height onwards.
            //
            // This does imply that assumed-valid blocks will be re-downloaded, but it is
            // also possible that in the intervening time, a chain reorg has occurred that
            // orphaned some of those blocks.
            db_cache
                .truncate(rewind_height)
                .await
                .map_err(Error::Cache)?;

            // The database was truncated, invalidating prior suggested ranges.
            Ok(true)
        }
        Ok(_) => {
            // If scanning these blocks caused a suggested range to be added that has a
            // higher priority than the current range, invalidate the current ranges.
            let latest_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;

            Ok(if let Some(range) = latest_ranges.first() {
                range.priority() > scan_range.priority()
            } else {
                false
            })
        }
        Err(e) => Err(e.into()),
    }
}

/// Refreshes the given account's view of UTXOs that exist starting at the given height.
///
/// ## Note about UTXO tracking
///
/// (Extracted from [a comment in the Android SDK].)
///
/// We no longer clear UTXOs here, as `WalletDb::put_received_transparent_utxo` now uses
/// an upsert instead of an insert. This means that now-spent UTXOs would previously have
/// been deleted, but now are left in the database (like shielded notes).
///
/// Due to the fact that the `lightwalletd` query only returns _current_ UTXOs, we don't
/// learn about recently-spent UTXOs here, so the transparent balance does not get updated
/// here.
///
/// Instead, when a received shielded note is "enhanced" by downloading the full
/// transaction, we mark any UTXOs spent in that transaction as spent in the database.
/// This relies on two current properties:
/// - UTXOs are only ever spent in shielding transactions.
/// - At least one shielded note from each shielding transaction is always enhanced.
///
/// However, for greater reliability, we may want to alter the Data Access API to support
/// "inferring spentness" from what is _not_ returned as a UTXO, or alternatively fetch
/// TXOs from `lightwalletd` instead of just UTXOs.
///
/// [a comment in the Android SDK]: https://github.com/Electric-Coin-Company/zcash-android-wallet-sdk/blob/855204fc8ae4057fdac939f98df4aa38c8e662f1/sdk-lib/src/main/java/cash/z/ecc/android/sdk/block/processor/CompactBlockProcessor.kt#L979-L991
#[cfg(all(feature = "sync", feature = "transparent-inputs"))]
async fn refresh_utxos<P, ChT, DbT, CaErr, TrErr>(
    params: &P,
    client: &mut CompactTxStreamerClient<ChT>,
    db_data: &mut DbT,
    account_id: DbT::AccountId,
    start_height: BlockHeight,
) -> Result<(), Error<CaErr, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletWrite,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let request = service::GetAddressUtxosArg {
        addresses: db_data
            .get_transparent_receivers(account_id, true, true)
            .map_err(Error::Wallet)?
            .into_keys()
            .map(|addr| addr.encode(params))
            .collect(),
        start_height: start_height.into(),
        max_entries: 0,
    };

    if request.addresses.is_empty() {
        info!("{:?} has no transparent receivers", account_id);
    } else {
        client
            .get_address_utxos_stream(request)
            .await?
            .into_inner()
            .map_err(Error::Server)
            .and_then(|reply| async move {
                WalletTransparentOutput::from_parts(
                    OutPoint::new(
                        reply.txid[..]
                            .try_into()
                            .map_err(|_| Error::MisbehavingServer)?,
                        reply
                            .index
                            .try_into()
                            .map_err(|_| Error::MisbehavingServer)?,
                    ),
                    TxOut::new(
                        Zatoshis::from_nonnegative_i64(reply.value_zat)
                            .map_err(|_| Error::MisbehavingServer)?,
                        Script(script::Code(reply.script)),
                    ),
                    Some(
                        BlockHeight::try_from(reply.height)
                            .map_err(|_| Error::MisbehavingServer)?,
                    ),
                    Some(account_id),
                    None,
                    None,
                )
                .ok_or(Error::MisbehavingServer)
            })
            .try_for_each(|output| {
                let res = db_data.put_received_transparent_utxo(&output).map(|_| ());
                async move { res.map_err(Error::Wallet) }
            })
            .await?;
    }

    Ok(())
}

/// Errors that can occur while syncing.
#[cfg(feature = "sync")]
#[derive(Debug)]
pub enum Error<CaErr, DbErr, TrErr> {
    /// An error while interacting with a [`BlockCache`].
    Cache(CaErr),
    /// The lightwalletd server returned invalid information, and is misbehaving.
    MisbehavingServer,
    /// An error while scanning blocks.
    Scan(ScanError),
    /// An error while communicating with the lightwalletd server.
    Server(tonic::Status),
    /// An error while interacting with a wallet database via [`WalletRead`] or
    /// [`WalletWrite`].
    Wallet(DbErr),
    /// An error while interacting with a wallet database via [`WalletCommitmentTrees`].
    WalletTrees(ShardTreeError<TrErr>),
}

#[cfg(feature = "sync")]
impl<CaErr, DbErr, TrErr> fmt::Display for Error<CaErr, DbErr, TrErr>
where
    CaErr: fmt::Display,
    DbErr: fmt::Display,
    TrErr: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cache(e) => write!(f, "Error while interacting with block cache: {e}"),
            Error::MisbehavingServer => write!(f, "lightwalletd server is misbehaving"),
            Error::Scan(e) => write!(f, "Error while scanning blocks: {e}"),
            Error::Server(e) => {
                write!(f, "Error while communicating with lightwalletd server: {e}")
            }
            Error::Wallet(e) => write!(f, "Error while interacting with wallet database: {e}"),
            Error::WalletTrees(e) => write!(
                f,
                "Error while interacting with wallet commitment trees: {e}"
            ),
        }
    }
}

#[cfg(feature = "sync")]
impl<CaErr, DbErr, TrErr> std::error::Error for Error<CaErr, DbErr, TrErr>
where
    CaErr: std::error::Error,
    DbErr: std::error::Error,
    TrErr: std::error::Error,
{
}

#[cfg(feature = "sync")]
impl<CaErr, DbErr, TrErr> From<ChainError<DbErr, CaErr>> for Error<CaErr, DbErr, TrErr> {
    fn from(e: ChainError<DbErr, CaErr>) -> Self {
        match e {
            ChainError::Wallet(e) => Error::Wallet(e),
            ChainError::BlockSource(e) => Error::Cache(e),
            ChainError::Scan(e) => Error::Scan(e),
        }
    }
}

#[cfg(feature = "sync")]
impl<CaErr, DbErr, TrErr> From<tonic::Status> for Error<CaErr, DbErr, TrErr> {
    fn from(status: tonic::Status) -> Self {
        Error::Server(status)
    }
}

#[cfg(all(test, feature = "sync", feature = "orchard"))]
mod tests {
    use std::{
        collections::BTreeMap,
        convert::Infallible,
        future::{Future, Ready, ready},
        ops::Range,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use async_trait::async_trait;
    use tonic::{
        Status,
        body::Body as TonicBody,
        codec::{BufferSettings, EncodeBody, SingleMessageCompressionOverride, Streaming},
        codegen::{Service, http::Request, http::Response, tokio_stream},
    };
    use tonic_prost::{ProstDecoder, ProstEncoder};
    use zcash_protocol::consensus::{BlockHeight, Network};

    use crate::{
        data_api::{
            chain::{BlockCache, BlockSource, error::Error as ChainError},
            scanning::{ScanPriority, ScanRange},
            testing::MockWalletDb,
        },
        proto::{
            compact_formats::{ChainMetadata, CompactBlock},
            service::{
                self, BlockId, BlockRange, TreeState,
                compact_tx_streamer_client::CompactTxStreamerClient,
            },
        },
    };

    use super::{BatchBudget, BudgetState, StepOptions, run, run_step, update_subtree_roots};

    #[derive(Clone)]
    struct CountingGrpcService(Arc<AtomicUsize>);

    impl Service<Request<TonicBody>> for CountingGrpcService {
        type Response = Response<TonicBody>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request<TonicBody>) -> Self::Future {
            self.0.fetch_add(1, Ordering::Relaxed);
            ready(Ok(Response::builder()
                .header("content-type", "application/grpc")
                .header("grpc-status", "0")
                .body(TonicBody::empty())
                .unwrap()))
        }
    }

    #[test]
    fn subtree_root_sync_requests_all_pools() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let mut client =
            CompactTxStreamerClient::new(CountingGrpcService(Arc::clone(&request_count)));
        let mut wallet = MockWalletDb::new(Network::TestNetwork);

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            update_subtree_roots::<_, _, Infallible, Infallible>(&mut client, &mut wallet)
                .await
                .unwrap();
        });

        assert_eq!(request_count.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn batch_budget_counts_down_to_exhaustion() {
        let mut budget = BatchBudget::new(3);
        assert_eq!(budget.record_batch(), BudgetState::Remaining);
        assert_eq!(budget.record_batch(), BudgetState::Remaining);
        assert_eq!(budget.record_batch(), BudgetState::Exhausted);
        // Once exhausted, the budget stays exhausted.
        assert_eq!(budget.record_batch(), BudgetState::Exhausted);
    }

    #[test]
    fn batch_budget_always_permits_one_batch() {
        // A zero budget is treated as a budget of one, so a step always makes progress.
        assert_eq!(BatchBudget::new(0), BatchBudget::new(1));
        assert_eq!(BatchBudget::new(0).record_batch(), BudgetState::Exhausted);
    }

    #[test]
    fn batch_budget_unbounded_never_exhausts() {
        let mut budget = BatchBudget::new(usize::MAX);
        for _ in 0..1000 {
            assert_eq!(budget.record_batch(), BudgetState::Remaining);
        }
    }

    // --- Mock lightwalletd ----------------------------------------------------------------

    /// A deterministic hash for the block at the given height, so that consecutive blocks
    /// served by the mock server pass the scanner's `prev_hash` continuity check.
    fn block_hash(height: u32) -> Vec<u8> {
        let mut hash = vec![0x5a; 32];
        hash[..4].copy_from_slice(&height.to_le_bytes());
        hash
    }

    fn compact_block(height: u32) -> CompactBlock {
        CompactBlock {
            height: height.into(),
            hash: block_hash(height),
            prev_hash: block_hash(height - 1),
            chain_metadata: Some(ChainMetadata::default()),
            ..Default::default()
        }
    }

    /// Encodes a server-side gRPC response body carrying the given messages followed by an
    /// OK status in the trailers, exactly as a real server would.
    fn grpc_response<M: prost::Message + Send + 'static>(messages: Vec<M>) -> Response<TonicBody> {
        let body = EncodeBody::new_server(
            ProstEncoder::<M>::new(BufferSettings::default()),
            tokio_stream::iter(messages.into_iter().map(Ok::<_, Status>)),
            None,
            SingleMessageCompressionOverride::default(),
            None,
        );
        Response::builder()
            .header("content-type", "application/grpc")
            .body(TonicBody::new(body))
            .unwrap()
    }

    /// Decodes the single message of a unary gRPC request body.
    async fn grpc_request<M: prost::Message + Default + Send + 'static>(body: TonicBody) -> M {
        let mut stream = Streaming::<M>::new_request(
            ProstDecoder::<M>::new(BufferSettings::default()),
            body,
            None,
            None,
        );
        stream
            .message()
            .await
            .expect("request body decodes")
            .expect("request body contains a message")
    }

    /// A `CompactTxStreamer` serving an empty chain of blocks with deterministic hashes, up
    /// to `tip_height`. It records the path of every request it receives.
    #[derive(Clone)]
    struct MockLightwalletd {
        tip_height: u32,
        request_paths: Arc<Mutex<Vec<String>>>,
    }

    impl MockLightwalletd {
        fn new(tip_height: u32) -> Self {
            Self {
                tip_height,
                request_paths: Arc::new(Mutex::new(vec![])),
            }
        }

        fn requests_for(&self, method: &str) -> usize {
            self.request_paths
                .lock()
                .unwrap()
                .iter()
                .filter(|p| p.ends_with(method))
                .count()
        }
    }

    impl Service<Request<TonicBody>> for MockLightwalletd {
        type Response = Response<TonicBody>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<TonicBody>) -> Self::Future {
            let (parts, body) = request.into_parts();
            let path = parts.uri.path().to_string();
            self.request_paths.lock().unwrap().push(path.clone());
            let tip_height = self.tip_height;

            Box::pin(async move {
                let method = path.rsplit('/').next().unwrap_or_default();
                let response = match method {
                    "GetLatestBlock" => grpc_response(vec![BlockId {
                        height: tip_height.into(),
                        hash: block_hash(tip_height),
                    }]),
                    "GetBlockRange" => {
                        let range: BlockRange = grpc_request(body).await;
                        let start = range.start.expect("start is set").height as u32;
                        let end = range.end.expect("end is set").height as u32;
                        assert!(start <= end, "mock server only serves ascending ranges");
                        assert!(end <= tip_height, "requested blocks beyond the chain tip");
                        grpc_response((start..=end).map(compact_block).collect())
                    }
                    "GetTreeState" => {
                        let block: BlockId = grpc_request(body).await;
                        let height = block.height as u32;
                        grpc_response(vec![TreeState {
                            network: "test".into(),
                            height: height.into(),
                            hash: hex::encode(block_hash(height)),
                            time: 0,
                            sapling_tree: String::new(),
                            orchard_tree: String::new(),
                            ironwood_tree: String::new(),
                        }])
                    }
                    "GetSubtreeRoots" => grpc_response(Vec::<service::SubtreeRoot>::new()),
                    other => panic!("unexpected request to mock lightwalletd: {other}"),
                };
                Ok(response)
            })
        }
    }

    // --- In-memory block cache ------------------------------------------------------------

    /// An in-memory [`BlockCache`] that records the block range of every `insert` call, which
    /// corresponds one-to-one with the batches the sync flow downloads and scans.
    #[derive(Default)]
    struct MemBlockCache {
        blocks: Mutex<BTreeMap<u32, CompactBlock>>,
        inserted_ranges: Mutex<Vec<Range<u32>>>,
    }

    impl MemBlockCache {
        fn inserted_ranges(&self) -> Vec<Range<u32>> {
            self.inserted_ranges.lock().unwrap().clone()
        }

        fn cached_heights(&self) -> Vec<u32> {
            self.blocks.lock().unwrap().keys().copied().collect()
        }
    }

    impl BlockSource for MemBlockCache {
        type Error = Infallible;

        fn with_blocks<F, WalletErrT>(
            &self,
            from_height: Option<BlockHeight>,
            limit: Option<usize>,
            mut with_block: F,
        ) -> Result<(), ChainError<WalletErrT, Self::Error>>
        where
            F: FnMut(CompactBlock) -> Result<(), ChainError<WalletErrT, Self::Error>>,
        {
            let blocks = self.blocks.lock().unwrap();
            let from = from_height.map_or(0, u32::from);
            let selected = blocks
                .range(from..)
                .take(limit.unwrap_or(usize::MAX))
                .map(|(_, b)| b.clone())
                .collect::<Vec<_>>();
            drop(blocks);
            for block in selected {
                with_block(block)?;
            }
            Ok(())
        }
    }

    #[async_trait]
    impl BlockCache for MemBlockCache {
        fn get_tip_height(
            &self,
            range: Option<&ScanRange>,
        ) -> Result<Option<BlockHeight>, Self::Error> {
            let blocks = self.blocks.lock().unwrap();
            Ok(blocks
                .keys()
                .filter(|h| range.is_none_or(|r| r.block_range().contains(&(**h).into())))
                .max()
                .map(|h| BlockHeight::from_u32(*h)))
        }

        async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
            let start = u32::from(range.block_range().start);
            let end = u32::from(range.block_range().end);
            Ok(self
                .blocks
                .lock()
                .unwrap()
                .range(start..end)
                .map(|(_, b)| b.clone())
                .collect())
        }

        async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
            let heights = compact_blocks.iter().map(|b| b.height as u32);
            if let Some((min, max)) = heights.clone().min().zip(heights.max()) {
                self.inserted_ranges.lock().unwrap().push(min..max + 1);
            }
            let mut blocks = self.blocks.lock().unwrap();
            for block in compact_blocks {
                blocks.insert(block.height as u32, block);
            }
            Ok(())
        }

        async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
            let start = u32::from(range.block_range().start);
            let end = u32::from(range.block_range().end);
            self.blocks
                .lock()
                .unwrap()
                .retain(|h, _| !(start..end).contains(h));
            Ok(())
        }
    }

    // --- run_step tests -------------------------------------------------------------------

    const BATCH_SIZE: u32 = 10;
    const TIP_HEIGHT: u32 = 1050;

    fn scan_range(range: Range<u32>, priority: ScanPriority) -> ScanRange {
        ScanRange::from_parts(
            BlockHeight::from_u32(range.start)..BlockHeight::from_u32(range.end),
            priority,
        )
    }

    /// The scan queue every test starts from: a `Verify` range (handled by the verification
    /// loop, which downloads the whole range as one batch) followed by a `Historic` range that
    /// the main loop splits into `BATCH_SIZE` batches, the last of which is short.
    fn initial_scan_queue() -> Vec<ScanRange> {
        vec![
            scan_range(1030..1045, ScanPriority::Verify),
            scan_range(1000..1025, ScanPriority::Historic),
        ]
    }

    /// The batches `run` is expected to download and scan for `initial_scan_queue`.
    fn expected_batches() -> Vec<Range<u32>> {
        vec![1030..1045, 1000..1010, 1010..1020, 1020..1025]
    }

    struct Harness {
        server: MockLightwalletd,
        client: CompactTxStreamerClient<MockLightwalletd>,
        cache: MemBlockCache,
        wallet: MockWalletDb,
    }

    impl Harness {
        fn new() -> Self {
            let server = MockLightwalletd::new(TIP_HEIGHT);
            let client = CompactTxStreamerClient::new(server.clone());
            let mut wallet = MockWalletDb::new(Network::TestNetwork);
            wallet.set_scan_queue(initial_scan_queue());
            Self {
                server,
                client,
                cache: MemBlockCache::default(),
                wallet,
            }
        }

        async fn run(&mut self) {
            run(
                &mut self.client,
                &Network::TestNetwork,
                &self.cache,
                &mut self.wallet,
                BATCH_SIZE,
            )
            .await
            .unwrap()
        }

        async fn run_step(&mut self, opts: StepOptions) -> bool {
            run_step(
                &mut self.client,
                &Network::TestNetwork,
                &self.cache,
                &mut self.wallet,
                BATCH_SIZE,
                opts,
            )
            .await
            .unwrap()
        }

        fn remaining_ranges(&self) -> Vec<ScanRange> {
            self.wallet.suggest_scan_ranges().unwrap()
        }
    }

    use crate::data_api::WalletRead as _;

    #[test]
    fn run_scans_all_batches_and_clears_cache() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut h = Harness::new();
            h.run().await;

            assert_eq!(h.cache.inserted_ranges(), expected_batches());
            assert!(h.remaining_ranges().is_empty());
            assert!(h.cache.cached_heights().is_empty());
            assert_eq!(h.server.requests_for("GetSubtreeRoots"), 3);
        });
    }

    #[test]
    fn run_step_single_batch_matches_run() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut h = Harness::new();
            let first = StepOptions {
                refresh_subtree_roots: true,
                max_batches: 1,
            };
            let later = StepOptions {
                refresh_subtree_roots: false,
                max_batches: 1,
            };

            // The first step refreshes the subtree roots (one request per pool) and scans
            // exactly one batch: the Verify range, as a single batch.
            assert!(h.run_step(first).await);
            assert_eq!(h.server.requests_for("GetSubtreeRoots"), 3);
            assert_eq!(h.cache.inserted_ranges(), vec![1030..1045]);
            assert_eq!(
                h.remaining_ranges(),
                vec![scan_range(1000..1025, ScanPriority::Historic)]
            );
            // Scanned blocks have been deleted before the step returned.
            assert!(h.cache.cached_heights().is_empty());

            // Each further step scans one batch and leaves the remainder queued.
            assert!(h.run_step(later).await);
            assert_eq!(
                h.remaining_ranges(),
                vec![scan_range(1010..1025, ScanPriority::Historic)]
            );
            assert!(h.cache.cached_heights().is_empty());

            assert!(h.run_step(later).await);
            assert_eq!(
                h.remaining_ranges(),
                vec![scan_range(1020..1025, ScanPriority::Historic)]
            );

            // The final batch exhausts the budget, so the step still reports more work; the
            // next step finds nothing to do and reports completion without scanning.
            assert!(h.run_step(later).await);
            assert!(h.remaining_ranges().is_empty());
            assert!(!h.run_step(later).await);

            assert_eq!(h.cache.inserted_ranges(), expected_batches());
            assert!(h.cache.cached_heights().is_empty());
            // Only the first step refreshed the subtree roots.
            assert_eq!(h.server.requests_for("GetSubtreeRoots"), 3);
            // Each step refreshed the chain tip.
            assert_eq!(h.server.requests_for("GetLatestBlock"), 5);
        });
    }

    #[test]
    fn run_step_reports_completion_when_queue_drains_within_budget() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut h = Harness::new();
            let opts = StepOptions {
                refresh_subtree_roots: false,
                max_batches: 3,
            };

            // Four batches in total: the first step scans three, the second scans the last
            // one and then observes an empty queue, so it reports completion directly.
            assert!(h.run_step(opts).await);
            assert_eq!(
                h.cache.inserted_ranges(),
                vec![1030..1045, 1000..1010, 1010..1020]
            );
            assert_eq!(
                h.remaining_ranges(),
                vec![scan_range(1020..1025, ScanPriority::Historic)]
            );

            assert!(!h.run_step(opts).await);
            assert_eq!(h.cache.inserted_ranges(), expected_batches());
            assert!(h.remaining_ranges().is_empty());
            assert!(h.cache.cached_heights().is_empty());
        });
    }

    #[test]
    fn run_step_unbounded_behaves_like_run() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut h = Harness::new();
            let opts = StepOptions {
                refresh_subtree_roots: true,
                max_batches: usize::MAX,
            };

            assert!(!h.run_step(opts).await);
            assert_eq!(h.cache.inserted_ranges(), expected_batches());
            assert!(h.remaining_ranges().is_empty());
            assert!(h.cache.cached_heights().is_empty());
        });
    }

    #[test]
    fn run_step_with_nothing_to_do_reports_completion() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut h = Harness::new();
            h.wallet.set_scan_queue(vec![]);
            let opts = StepOptions {
                refresh_subtree_roots: false,
                max_batches: 1,
            };

            assert!(!h.run_step(opts).await);
            assert!(h.cache.inserted_ranges().is_empty());
            assert_eq!(h.server.requests_for("GetLatestBlock"), 1);
        });
    }
}
