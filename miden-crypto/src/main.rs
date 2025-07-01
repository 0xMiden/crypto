use std::{path::PathBuf, time::Instant};

use clap::Parser;
#[cfg(not(feature = "rocksdb"))]
use miden_crypto::merkle::MemoryStorage;
#[cfg(feature = "rocksdb")]
use miden_crypto::merkle::{RocksDbConfig, RocksDbStorage};

use miden_crypto::{
    EMPTY_WORD, Felt, ONE, Word,
    hash::rpo::{Rpo256, RpoDigest},
    merkle::{LargeSmt, MerkleError},
};
use rand::{Rng, prelude::IteratorRandom, rng};
use rand_utils::rand_value;

#[cfg(feature = "rocksdb")]
type Storage = RocksDbStorage;

#[cfg(not(feature = "rocksdb"))]
type Storage = MemoryStorage;

#[derive(Parser, Debug)]
#[clap(name = "Benchmark", about = "SMT benchmark", version, rename_all = "kebab-case")]
pub struct BenchmarkCmd {
    /// Size of the tree
    #[clap(short = 's', long = "size", default_value = "1000000")]
    size: usize,
    /// Number of insertions
    #[clap(short = 'i', long = "insertions", default_value = "10000")]
    insertions: usize,
    /// Number of updates
    #[clap(short = 'u', long = "updates", default_value = "10000")]
    updates: usize,
    /// Path for the benchmark database
    #[clap(short = 'p', long = "path", default_value = "/mnt/rocksdb/benchmark_db")]
    storage_path: Option<PathBuf>,
    /// Open existing database and skip construction
    #[clap(short = 'o', long = "open", default_value = "false")]
    open: bool,
    /// Number of batch operations
    #[clap(short = 'b', long = "batches", default_value = "1")]
    batches: usize,
}

fn main() {
    benchmark_smt();
    println!("Benchmark completed successfully");
}

/// Run a benchmark for [`Smt`].
pub fn benchmark_smt() {
    let args = BenchmarkCmd::parse();
    let tree_size = args.size;
    let insertions = args.insertions;
    let updates = args.updates;
    let storage_path = args.storage_path;
    let batches = args.batches;

    if cfg!(feature = "rocksdb") {
        println!("Running benchmark with rocksdb storage");
    } else {
        println!("Running benchmark with memory storage");
    }
    assert!(updates <= tree_size, "Cannot update more than `size`");
    // prepare the `leaves` vector for tree creation
    let mut entries = Vec::new();
    for i in 0..tree_size {
        let key = rand_value::<RpoDigest>();
        let value = [ONE, ONE, ONE, Felt::new(i as u64)];
        entries.push((key, value));
    }

    let mut tree = if args.open {
        open_existing(storage_path).unwrap()
    } else {
        construction(entries.clone(), tree_size, storage_path).unwrap()
    };
    insertion(&mut tree, insertions).unwrap();
    for _ in 0..batches {
        batched_insertion(&mut tree, insertions).unwrap();
        batched_update(&mut tree, entries.clone(), updates).unwrap();
    }
    proof_generation(&mut tree).unwrap();
}

/// Runs the construction benchmark for [`Smt`], returning the constructed tree.
pub fn construction(
    entries: Vec<(RpoDigest, Word)>,
    size: usize,
    database_path: Option<PathBuf>,
) -> Result<LargeSmt<Storage>, MerkleError> {
    println!("Running a construction benchmark:");
    let now = Instant::now();
    let storage = get_storage(database_path, false);
    let tree = LargeSmt::with_entries(storage, entries)?;
    let elapsed = now.elapsed().as_secs_f32();
    println!("Constructed an SMT with {size} key-value pairs in {elapsed:.1} seconds");
    println!("Number of leaf nodes: {}\n", tree.num_leaves());

    Ok(tree)
}

pub fn open_existing(storage_path: Option<PathBuf>) -> Result<LargeSmt<Storage>, MerkleError> {
    println!("Opening an existing database:");
    let now = Instant::now();
    let storage = get_storage(storage_path, true);
    let tree = LargeSmt::new(storage)?;
    let elapsed = now.elapsed().as_secs_f32();
    println!("Opened an existing database in {elapsed:.1} seconds");
    Ok(tree)
}
/// Runs the insertion benchmark for the [`Smt`].
pub fn insertion(tree: &mut LargeSmt<Storage>, insertions: usize) -> Result<(), MerkleError> {
    println!("Running an insertion benchmark:");

    let size = tree.num_leaves();
    let mut insertion_times = Vec::new();

    for i in 0..insertions {
        let test_key = Rpo256::hash(&rand_value::<u64>().to_be_bytes());
        let test_value = [ONE, ONE, ONE, Felt::new((size + i) as u64)];

        let now = Instant::now();
        tree.insert(test_key, test_value);
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

pub fn batched_insertion(
    tree: &mut LargeSmt<Storage>,
    insertions: usize,
) -> Result<(), MerkleError> {
    println!("Running a batched insertion benchmark:");

    let size = tree.num_leaves();

    let new_pairs: Vec<(RpoDigest, Word)> = (0..insertions)
        .map(|i| {
            let key = Rpo256::hash(&rand_value::<u64>().to_be_bytes());
            let value = [ONE, ONE, ONE, Felt::new((size + i) as u64)];
            (key, value)
        })
        .collect();

    let now = Instant::now();
    let mutations = tree.compute_mutations(new_pairs);
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

pub fn batched_update(
    tree: &mut LargeSmt<Storage>,
    entries: Vec<(RpoDigest, Word)>,
    updates: usize,
) -> Result<(), MerkleError> {
    const REMOVAL_PROBABILITY: f64 = 0.2;

    println!("Running a batched update benchmark:");

    let size = tree.num_leaves();
    let mut rng = rng();

    let new_pairs =
        entries
            .into_iter()
            .choose_multiple(&mut rng, updates)
            .into_iter()
            .map(|(key, _)| {
                let value = if rng.random_bool(REMOVAL_PROBABILITY) {
                    EMPTY_WORD
                } else {
                    [ONE, ONE, ONE, Felt::new(rng.random())]
                };

                (key, value)
            });

    assert_eq!(new_pairs.len(), updates);

    let now = Instant::now();
    let mutations = tree.compute_mutations(new_pairs);
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

/// Runs the proof generation benchmark for the [`Smt`].
pub fn proof_generation(tree: &mut LargeSmt<Storage>) -> Result<(), MerkleError> {
    const NUM_PROOFS: usize = 100;

    println!("Running a proof generation benchmark:");

    let mut opening_times = Vec::new();
    let size = tree.num_leaves();

    // fetch keys already in the tree to be opened
    let keys = tree
        .leaves()
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
fn get_storage(database_path: Option<PathBuf>, open: bool) -> Storage {
    let path = database_path.unwrap_or_else(|| std::env::temp_dir().join("miden_crypto_benchmark"));
    println!("Using database path: {}", path.display());
    if !open {
        // delete the folder if it exists as we are creating a new database
        if path.exists() {
            std::fs::remove_dir_all(path.clone()).unwrap();
        }
        std::fs::create_dir_all(path.clone()).expect("Failed to create database directory");
    }
    Storage::open(RocksDbConfig::new(path).with_cache_size(1 << 30).with_max_open_files(1024)).expect("Failed to open database")
}

#[cfg(not(feature = "rocksdb"))]
fn get_storage(_database_path: Option<PathBuf>, _open: bool) -> Storage {
    Storage::new()
}
