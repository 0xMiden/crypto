#[cfg(feature = "rocksdb")]
use std::collections::BTreeSet;
use std::{path::PathBuf, time::Instant};

use clap::{Parser, ValueEnum};
#[cfg(feature = "rocksdb")]
use miden_crypto::merkle::{
    EmptySubtreeRoots, MerkleError, PersistedSmtForest, RocksDbForestConfig, SMT_DEPTH,
};
#[cfg(feature = "rocksdb")]
use miden_crypto::merkle::{RocksDbConfig, RocksDbStorage};
#[cfg(feature = "rocksdb")]
use miden_crypto::word::LexicographicWord;
use miden_crypto::{
    EMPTY_WORD, Felt, ONE, Word,
    hash::rpo::Rpo256,
    merkle::{LargeSmt, LargeSmtError, MemoryStorage, SmtStorage},
};
use rand::{Rng, prelude::IteratorRandom, rng};
use rand_utils::rand_value;

type Storage = Box<dyn SmtStorage>;

#[derive(Parser, Debug)]
#[command(name = "Benchmark", about = "SMT benchmark", version, rename_all = "kebab-case")]
pub struct BenchmarkCmd {
    /// Size of the tree
    #[arg(short = 's', long = "size", default_value = "1000000")]
    size: usize,
    /// Number of insertions
    #[arg(short = 'i', long = "insertions", default_value = "10000")]
    insertions: usize,
    /// Number of updates
    #[arg(short = 'u', long = "updates", default_value = "10000")]
    updates: usize,
    /// Path for the benchmark database
    #[clap(short = 'p', long = "path")]
    storage_path: Option<PathBuf>,
    /// Open existing database and skip construction
    #[clap(short = 'o', long = "open", default_value = "false")]
    open: bool,
    /// Number of batch operations
    #[clap(short = 'b', long = "batches", default_value = "1")]
    batches: usize,
    /// Storage backend to use at runtime: memory or rocksdb
    #[arg(short = 's', long = "storage", value_enum, default_value = "memory")]
    storage: StorageKind,
    /// Tree implementation to benchmark
    #[arg(long = "tree", value_enum, default_value = "large-smt")]
    tree: TreeKind,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum StorageKind {
    Memory,
    Rocksdb,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum TreeKind {
    LargeSmt,
    #[cfg(feature = "rocksdb")]
    PersistedForest,
}

fn main() {
    benchmark_smt();
    println!("Benchmark completed successfully");
}

/// Run a benchmark for [`Smt`].
pub fn benchmark_smt() {
    let BenchmarkCmd {
        size: tree_size,
        insertions,
        updates,
        storage_path,
        open,
        batches,
        storage,
        tree,
    } = BenchmarkCmd::parse();

    println!(
        "Running benchmark with {} storage",
        match storage {
            StorageKind::Memory => "memory",
            StorageKind::Rocksdb => "rocksdb",
        }
    );
    println!(
        "Benchmarking {} implementation",
        match tree {
            TreeKind::LargeSmt => "LargeSmt",
            #[cfg(feature = "rocksdb")]
            TreeKind::PersistedForest => "PersistedSmtForest",
        }
    );

    assert!(updates <= tree_size, "Cannot update more than `size`");

    // prepare the `leaves` vector for tree creation
    let mut entries = Vec::with_capacity(tree_size);
    for i in 0..tree_size {
        let key = rand_value::<Word>();
        let value = Word::new([ONE, ONE, ONE, Felt::new(i as u64)]);
        entries.push((key, value));
    }

    match tree {
        TreeKind::LargeSmt => {
            let mut tree = if open {
                large_smt_open_existing(storage_path.clone(), storage).unwrap()
            } else {
                large_smt_construction(entries.clone(), tree_size, storage_path.clone(), storage)
                    .unwrap()
            };
            large_smt_insertion(&mut tree, insertions).unwrap();
            for _ in 0..batches {
                large_smt_batched_insertion(&mut tree, insertions).unwrap();
                large_smt_batched_update(&mut tree, &entries, updates).unwrap();
            }
            large_smt_proof_generation(&mut tree).unwrap();
        },
        #[cfg(feature = "rocksdb")]
        TreeKind::PersistedForest => {
            if storage != StorageKind::Rocksdb {
                eprintln!("PersistedSmtForest benchmarking requires the rocksdb storage backend");
                std::process::exit(1);
            }
            if open {
                eprintln!("Opening existing persisted forests is not supported by this benchmark");
                std::process::exit(1);
            }

            let mut state =
                persisted_forest_construction(&entries, tree_size, storage_path.clone()).unwrap();
            persisted_forest_insertion(&mut state, insertions).unwrap();
            for _ in 0..batches {
                persisted_forest_batched_insertion(&mut state, insertions).unwrap();
                persisted_forest_batched_update(&mut state, &entries, updates).unwrap();
            }
            persisted_forest_proof_generation(&mut state).unwrap();
        },
    }
}

/// Runs the construction benchmark for [`LargeSmt`], returning the constructed tree.
pub fn large_smt_construction(
    entries: Vec<(Word, Word)>,
    size: usize,
    database_path: Option<PathBuf>,
    storage: StorageKind,
) -> Result<LargeSmt<Storage>, LargeSmtError> {
    println!("Running a construction benchmark:");
    let now = Instant::now();
    let storage = get_storage(database_path, false, storage);
    let tree = LargeSmt::with_entries(storage, entries)?;
    let elapsed = now.elapsed().as_secs_f32();
    println!("Constructed an SMT with {size} key-value pairs in {elapsed:.1} seconds");
    println!("Number of leaf nodes: {}\n", tree.num_leaves()?);

    Ok(tree)
}

pub fn large_smt_open_existing(
    storage_path: Option<PathBuf>,
    storage: StorageKind,
) -> Result<LargeSmt<Storage>, LargeSmtError> {
    println!("Opening an existing database:");
    let now = Instant::now();
    let storage = get_storage(storage_path, true, storage);
    let tree = LargeSmt::new(storage)?;
    let elapsed = now.elapsed().as_secs_f32();
    println!("Opened an existing database in {elapsed:.1} seconds");
    Ok(tree)
}
/// Runs the insertion benchmark for [`LargeSmt`].
pub fn large_smt_insertion(
    tree: &mut LargeSmt<Storage>,
    insertions: usize,
) -> Result<(), LargeSmtError> {
    println!("Running an insertion benchmark:");

    let size = tree.num_leaves()?;
    let mut insertion_times = Vec::new();

    for i in 0..insertions {
        let test_key = Rpo256::hash(&rand_value::<u64>().to_be_bytes());
        let test_value = Word::new([ONE, ONE, ONE, Felt::new((size + i) as u64)]);

        let now = Instant::now();
        tree.insert(test_key, test_value)?;
        let elapsed = now.elapsed();
        insertion_times.push(elapsed.as_micros());
    }

    println!(
        "The average insertion time measured by {insertions} inserts into an SMT with {size} leaves is {:.0} μs\n",
        // calculate the average
        insertion_times.iter().sum::<u128>() as f64 / (insertions as f64),
    );

    Ok(())
}

pub fn large_smt_batched_insertion(
    tree: &mut LargeSmt<Storage>,
    insertions: usize,
) -> Result<(), LargeSmtError> {
    println!("Running a batched insertion benchmark:");

    let size = tree.num_leaves()?;

    let new_pairs: Vec<(Word, Word)> = (0..insertions)
        .map(|i| {
            let key = Rpo256::hash(&rand_value::<u64>().to_be_bytes());
            let value = Word::new([ONE, ONE, ONE, Felt::new((size + i) as u64)]);
            (key, value)
        })
        .collect();

    let now = Instant::now();
    let mutations = tree.compute_mutations(new_pairs)?;
    let compute_elapsed = now.elapsed().as_secs_f64() * 1000_f64; // time in ms

    println!(
        "The average insert-batch computation time measured by a {insertions}-batch into an SMT with {size} leaves over {:.1} ms is {:.0} μs",
        compute_elapsed,
        compute_elapsed * 1000_f64 / insertions as f64, // time in μs
    );

    let now = Instant::now();
    tree.apply_mutations(mutations)?;
    let apply_elapsed = now.elapsed().as_secs_f64() * 1000_f64; // time in ms

    println!(
        "The average insert-batch application time measured by a {insertions}-batch into an SMT with {size} leaves over {:.1} ms is {:.0} μs",
        apply_elapsed,
        apply_elapsed * 1000_f64 / insertions as f64, // time in μs
    );

    println!(
        "The average batch insertion time measured by a {insertions}-batch into an SMT with {size} leaves totals to {:.1} ms",
        (compute_elapsed + apply_elapsed),
    );

    println!();

    Ok(())
}

pub fn large_smt_batched_update(
    tree: &mut LargeSmt<Storage>,
    entries: &[(Word, Word)],
    updates: usize,
) -> Result<(), LargeSmtError> {
    const REMOVAL_PROBABILITY: f64 = 0.2;

    println!("Running a batched update benchmark:");

    let size = tree.num_leaves()?;
    let mut rng = rng();

    let new_pairs =
        entries.iter().choose_multiple(&mut rng, updates).into_iter().map(|&(key, _)| {
            let value = if rng.random_bool(REMOVAL_PROBABILITY) {
                EMPTY_WORD
            } else {
                Word::new([ONE, ONE, ONE, Felt::new(rng.random())])
            };

            (key, value)
        });

    assert_eq!(new_pairs.len(), updates);

    let now = Instant::now();
    let mutations = tree.compute_mutations(new_pairs)?;
    let compute_elapsed = now.elapsed().as_secs_f64() * 1000_f64; // time in ms

    let now = Instant::now();
    tree.apply_mutations(mutations)?;
    let apply_elapsed = now.elapsed().as_secs_f64() * 1000_f64; // time in ms

    println!(
        "The average update-batch computation time measured by a {updates}-batch into an SMT with {size} leaves over {:.1} ms is {:.0} μs",
        compute_elapsed,
        compute_elapsed * 1000_f64 / updates as f64, // time in μs
    );

    println!(
        "The average update-batch application time measured by a {updates}-batch into an SMT with {size} leaves over {:.1} ms is {:.0} μs",
        apply_elapsed,
        apply_elapsed * 1000_f64 / updates as f64, // time in μs
    );

    println!(
        "The average batch update time measured by a {updates}-batch into an SMT with {size} leaves totals to {:.1} ms",
        (compute_elapsed + apply_elapsed),
    );

    println!();

    Ok(())
}

/// Runs the proof generation benchmark for [`LargeSmt`].
pub fn large_smt_proof_generation(tree: &mut LargeSmt<Storage>) -> Result<(), LargeSmtError> {
    const NUM_PROOFS: usize = 100;

    println!("Running a proof generation benchmark:");

    let mut opening_times = Vec::new();
    let size = tree.num_leaves()?;

    // fetch keys already in the tree to be opened
    let keys = tree
        .leaves()?
        .take(NUM_PROOFS)
        .map(|(_, leaf)| leaf.entries()[0].0)
        .collect::<Vec<_>>();

    for key in keys {
        let now = Instant::now();
        let _proof = tree.open(&key);
        opening_times.push(now.elapsed().as_micros());
    }

    println!(
        "The average proving time measured by {NUM_PROOFS} value proofs in an SMT with {size} leaves in {:.0} μs",
        // calculate the average
        opening_times.iter().sum::<u128>() as f64 / (NUM_PROOFS as f64),
    );

    Ok(())
}

#[cfg(feature = "rocksdb")]
struct PersistedForestBenchmarkState {
    forest: PersistedSmtForest,
    root: Word,
    keys: BTreeSet<LexicographicWord<Word>>,
}

#[cfg(feature = "rocksdb")]
fn persisted_forest_construction(
    entries: &[(Word, Word)],
    size: usize,
    database_path: Option<PathBuf>,
) -> Result<PersistedForestBenchmarkState, MerkleError> {
    println!("Running a construction benchmark:");
    let now = Instant::now();

    let config = get_forest_config(database_path, false);
    let mut forest = PersistedSmtForest::new(config)?;
    let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let root = forest.batch_insert(empty_root, entries.to_vec())?;
    let elapsed = now.elapsed().as_secs_f32();

    let mut keys = BTreeSet::new();
    persisted_forest_update_keys(&mut keys, entries);

    println!("Constructed an SMT with {size} key-value pairs in {elapsed:.1} seconds");
    println!("Number of leaf nodes: {}\n", keys.len());

    Ok(PersistedForestBenchmarkState { forest, root, keys })
}

#[cfg(feature = "rocksdb")]
fn persisted_forest_insertion(
    state: &mut PersistedForestBenchmarkState,
    insertions: usize,
) -> Result<(), MerkleError> {
    println!("Running an insertion benchmark:");

    let size = state.keys.len();
    let mut insertion_times = Vec::new();

    for i in 0..insertions {
        let test_key = Rpo256::hash(&rand_value::<u64>().to_be_bytes());
        let test_value = Word::new([ONE, ONE, ONE, Felt::new((size + i) as u64)]);

        let now = Instant::now();
        state.root = state.forest.insert(state.root, test_key, test_value)?;
        insertion_times.push(now.elapsed().as_micros());
        state.keys.insert(LexicographicWord::from(test_key));
    }

    println!(
        "The average insertion time measured by {insertions} inserts into an SMT with {size} leaves is {:.0} μs\n",
        insertion_times.iter().sum::<u128>() as f64 / (insertions as f64),
    );

    Ok(())
}

#[cfg(feature = "rocksdb")]
fn persisted_forest_batched_insertion(
    state: &mut PersistedForestBenchmarkState,
    insertions: usize,
) -> Result<(), MerkleError> {
    println!("Running a batched insertion benchmark:");

    let size = state.keys.len();
    let new_pairs: Vec<(Word, Word)> = (0..insertions)
        .map(|i| {
            let key = Rpo256::hash(&rand_value::<u64>().to_be_bytes());
            let value = Word::new([ONE, ONE, ONE, Felt::new((size + i) as u64)]);
            (key, value)
        })
        .collect();

    let now = Instant::now();
    state.root = state.forest.batch_insert(state.root, new_pairs.clone())?;
    let elapsed_ms = now.elapsed().as_secs_f64() * 1000_f64;

    persisted_forest_update_keys(&mut state.keys, &new_pairs);

    println!(
        "The average insert-batch execution time measured by a {insertions}-batch into an SMT with {size} leaves over {:.1} ms is {:.0} μs",
        elapsed_ms,
        elapsed_ms * 1000_f64 / insertions as f64,
    );
    println!(
        "The average batch insertion time measured by a {insertions}-batch into an SMT with {size} leaves totals to {:.1} ms",
        elapsed_ms,
    );
    println!();

    Ok(())
}

#[cfg(feature = "rocksdb")]
fn persisted_forest_batched_update(
    state: &mut PersistedForestBenchmarkState,
    entries: &[(Word, Word)],
    updates: usize,
) -> Result<(), MerkleError> {
    const REMOVAL_PROBABILITY: f64 = 0.2;

    println!("Running a batched update benchmark:");

    let size = state.keys.len();
    let mut rng = rng();

    let new_pairs: Vec<(Word, Word)> = entries
        .iter()
        .choose_multiple(&mut rng, updates)
        .into_iter()
        .map(|&(key, _)| {
            let value = if rng.random_bool(REMOVAL_PROBABILITY) {
                EMPTY_WORD
            } else {
                Word::new([ONE, ONE, ONE, Felt::new(rng.random())])
            };

            (key, value)
        })
        .collect();

    assert_eq!(new_pairs.len(), updates);

    let now = Instant::now();
    state.root = state.forest.batch_insert(state.root, new_pairs.clone())?;
    let elapsed_ms = now.elapsed().as_secs_f64() * 1000_f64;

    persisted_forest_update_keys(&mut state.keys, &new_pairs);

    println!(
        "The average update-batch execution time measured by a {updates}-batch into an SMT with {size} leaves over {:.1} ms is {:.0} μs",
        elapsed_ms,
        elapsed_ms * 1000_f64 / updates as f64,
    );
    println!(
        "The average batch update time measured by a {updates}-batch into an SMT with {size} leaves totals to {:.1} ms",
        elapsed_ms,
    );
    println!();

    Ok(())
}

#[cfg(feature = "rocksdb")]
fn persisted_forest_proof_generation(
    state: &PersistedForestBenchmarkState,
) -> Result<(), MerkleError> {
    const NUM_PROOFS: usize = 100;

    println!("Running a proof generation benchmark:");

    let available = state.keys.len().min(NUM_PROOFS);
    if available == 0 {
        println!("No keys available to generate proofs.\n");
        return Ok(());
    }

    let keys: Vec<Word> = state.keys.iter().take(available).map(|key| Word::from(*key)).collect();

    let mut opening_times = Vec::with_capacity(available);
    for key in keys {
        let now = Instant::now();
        let _proof = state.forest.open(state.root, key)?;
        opening_times.push(now.elapsed().as_micros());
    }

    println!(
        "The average proving time measured by {available} value proofs in an SMT with {} leaves in {:.0} μs",
        state.keys.len(),
        opening_times.iter().sum::<u128>() as f64 / (available as f64),
    );

    Ok(())
}

#[cfg(feature = "rocksdb")]
fn persisted_forest_update_keys(
    keys: &mut BTreeSet<LexicographicWord<Word>>,
    entries: &[(Word, Word)],
) {
    for (key, value) in entries {
        let key = LexicographicWord::from(*key);
        if *value == EMPTY_WORD {
            keys.remove(&key);
        } else {
            keys.insert(key);
        }
    }
}

#[cfg(feature = "rocksdb")]
fn get_forest_config(database_path: Option<PathBuf>, open: bool) -> RocksDbForestConfig {
    let path = database_path
        .unwrap_or_else(|| std::env::temp_dir().join("miden_crypto_persisted_forest_benchmark"));
    println!("Using forest database path: {}", path.display());
    if !open {
        if path.exists() {
            std::fs::remove_dir_all(&path).unwrap();
        }
        std::fs::create_dir_all(&path).expect("Failed to create forest database directory");
    }
    RocksDbForestConfig::new(path)
        .with_cache_size(1 << 30)
        .with_max_open_files(2048)
}

#[allow(unused_variables)]
fn get_storage(database_path: Option<PathBuf>, open: bool, kind: StorageKind) -> Storage {
    match kind {
        StorageKind::Memory => Box::new(MemoryStorage::new()),
        StorageKind::Rocksdb => {
            #[cfg(feature = "rocksdb")]
            {
                let path = database_path
                    .unwrap_or_else(|| std::env::temp_dir().join("miden_crypto_benchmark"));
                println!("Using database path: {}", path.display());
                if !open {
                    // delete the folder if it exists as we are creating a new database
                    if path.exists() {
                        std::fs::remove_dir_all(path.clone()).unwrap();
                    }
                    std::fs::create_dir_all(path.clone())
                        .expect("Failed to create database directory");
                }
                let db = RocksDbStorage::open(
                    RocksDbConfig::new(path).with_cache_size(1 << 30).with_max_open_files(2048),
                )
                .expect("Failed to open database");
                Box::new(db)
            }
            #[cfg(not(feature = "rocksdb"))]
            {
                eprintln!("rocksdb feature not enabled; falling back to memory storage");
                Box::new(MemoryStorage::new())
            }
        },
    }
}
