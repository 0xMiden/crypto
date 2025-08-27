// Benchmark macros to reduce boilerplate code
//
// This module provides procedural macros to eliminate repetitive
// patterns commonly found in benchmark code.

// Creates a unified hash benchmark macro that eliminates duplication
//
// This is the core macro that all other hash macros build upon.
// It supports custom throughput calculation and provides maximum flexibility.
//
// # Usage
// ```no_run
// benchmark_hash_core!(
//     hash_rpo256_elements,
//     "rpo256",
//     "elements",
//     HASH_ELEMENT_COUNTS,
//     |b, count| {
//         let elements = generate_felt_array_sequential(count);
//         b.iter(|| Rpo256::hash_elements(black_box(&elements)))
//     },
//     |count| Some(criterion::Throughput::Elements(count as u64))
// );
// ```
#[macro_export]
macro_rules! benchmark_hash_core {
    (
        $func_name:ident,
        $hasher_name:literal,
        $operation:literal,
        $sizes:expr,
        $closure:expr,
        $throughput:expr
    ) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-", $operation));
            group.sample_size(10);

            for size_ref in $sizes {
                let size_val = *size_ref;
                group.bench_with_input(
                    BenchmarkId::new($operation, size_val),
                    &size_val,
                    |b: &mut criterion::Bencher, &size_param: &usize| $closure(b, size_param),
                );

                if size_val > 0 {
                    let throughput_result = $throughput(size_val);
                    if let Some(ref t) = throughput_result {
                        group.throughput(t.clone());
                    }
                }
            }

            group.finish();
        }
    };
}

// Creates a benchmark for hash algorithms with common patterns (simplified interface)
//
// # Usage
// ```no_run
// benchmark_hash_simple!(hash_rpo256_single, "rpo256", "single", HASH_INPUT_SIZES, |b, size| {
//     let data = if size <= 64 {
//         generate_byte_array_sequential(size)
//     } else {
//         generate_byte_array_random(size)
//     };
//     b.iter(|| Rpo256::hash(black_box(&data)))
// });
// ```
#[macro_export]
macro_rules! benchmark_hash_simple {
    ($func_name:ident, $hasher_name:literal, $operation:literal, $sizes:expr, $closure:expr) => {
        $crate::benchmark_hash_core! {
            $func_name,
            $hasher_name,
            $operation,
            $sizes,
            $closure,
            |size| Some(criterion::Throughput::Bytes(size as u64))
        }
    };
}

// Creates a benchmark for hash algorithms with backward compatibility
// This macro maintains the original interface for existing code
//
// # Usage
// ```no_run
// benchmark_hash!(hash_rpo256_bytes, "rpo256", "bytes", HASH_INPUT_SIZES, |b, size| {
//     let data = generate_byte_array_sequential(size);
//     b.iter(|| Rpo256::hash(black_box(&data)))
// });
// ```
#[macro_export]
macro_rules! benchmark_hash {
    (
        $func_name:ident,
        $hasher_name:literal,
        $operation:literal,
        $sizes:expr,
        $closure:expr,
        $size_var:ident,
        $throughput:expr
    ) => {
        $crate::benchmark_hash_core! {
            $func_name,
            $hasher_name,
            $operation,
            $sizes,
            $closure,
            $throughput
        }
    };
    ($func_name:ident, $hasher_name:literal, $operation:literal, $sizes:expr, $closure:expr) => {
        $crate::benchmark_hash_core! {
            $func_name,
            $hasher_name,
            $operation,
            $sizes,
            $closure,
            |size| Some(criterion::Throughput::Bytes(size as u64))
        }
    };
}

// Creates a benchmark with automatic data generation for hash operations
//
// # Usage
// ```rust
// benchmark_hash_auto!(hash_rpo256_single, "rpo256", HASH_INPUT_SIZES, |b, data| {
//     b.iter(|| Rpo256::hash(black_box(data)))
// });
// ```
#[macro_export]
macro_rules! benchmark_hash_auto {
    ($func_name:ident, $hasher_name:literal, $sizes:expr, $closure:expr) => {
        $crate::benchmark_hash_simple!($func_name, $hasher_name, "single", $sizes, |b, size| {
            let data = if size <= 64 {
                $crate::common::data::generate_byte_array_sequential(size)
            } else {
                $crate::common::data::generate_byte_array_random(size)
            };
            $closure(b, &data)
        })
    };
}

// Creates a benchmark for hash merge operations
//
// # Usage
// ```no_run
// benchmark_hash_merge!(hash_rpo_merge, "rpo256", &[1, 2, 4, 8, 16], |b, size| {
//     // merge logic here
// });
// ```
#[macro_export]
macro_rules! benchmark_hash_merge {
    ($func_name:ident, $hasher_name:literal, $sizes:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-merge"));
            group.sample_size(10);

            for size_ref in $sizes {
                let size = *size_ref;
                group.bench_with_input(
                    BenchmarkId::new("merge", size),
                    &size,
                    |b: &mut criterion::Bencher, &size_param: &usize| $closure(b, size_param),
                );
            }

            group.finish();
        }
    };
}

// Creates a benchmark for hash felt operations with automatic throughput
//
// # Usage
// ```no_run
// benchmark_hash_felt!(
//     hash_rpo_elements,
//     "rpo256",
//     &[1, 2, 4, 8, 16, 32, 64, 128],
//     |b, count| {
//         let elements = generate_felt_array_sequential(count);
//         b.iter(|| Rpo256::hash_elements(black_box(&elements)))
//     },
//     |count| Some(criterion::Throughput::Elements(count as u64))
// );
// ```
#[macro_export]
macro_rules! benchmark_hash_felt {
    ($func_name:ident, $hasher_name:literal, $counts:expr, $closure:expr, $throughput:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-felt"));
            group.sample_size(10);

            for count_ref in $counts {
                let count = *count_ref;
                group.bench_with_input(
                    BenchmarkId::new("hash_elements", count),
                    &count,
                    |b: &mut criterion::Bencher, &count_param: &usize| $closure(b, count_param),
                );

                let throughput_result = $throughput(count);
                if let Some(ref t) = throughput_result {
                    group.throughput(t.clone());
                }
            }

            group.finish();
        }
    };
    ($func_name:ident, $hasher_name:literal, $counts:expr, $closure:expr) => {
        $crate::benchmark_hash_felt!($func_name, $hasher_name, $counts, $closure, |count| Some(
            criterion::Throughput::Elements(count as u64)
        ))
    };
}

// Creates a benchmark for hash merge domain operations
#[macro_export]
macro_rules! benchmark_hash_merge_domain {
    ($func_name:ident, $hasher_name:literal, $sizes:expr, $domains:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-merge-domain"));
            group.sample_size(10);

            for size_ref in $sizes {
                let size = *size_ref;
                for domain_ref in $domains {
                    let domain = *domain_ref;
                    group.bench_with_input(
                        BenchmarkId::new("merge_in_domain", format!("{}_{}", size, domain)),
                        &(size, domain),
                        |b: &mut criterion::Bencher, param_ref: &(usize, u64)| {
                            let (size_param, domain_param) = *param_ref;
                            $closure(b, (size_param, domain_param))
                        },
                    );
                }
            }

            group.finish();
        }
    };
}

// Creates a benchmark for hash merge with int operations
#[macro_export]
macro_rules! benchmark_hash_merge_with_int {
    ($func_name:ident, $hasher_name:literal, $sizes:expr, $int_sizes:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-merge-int"));
            group.sample_size(10);

            for size_ref in $sizes {
                let size = *size_ref;
                for int_size_ref in $int_sizes {
                    let int_size = *int_size_ref;
                    group.bench_with_input(
                        BenchmarkId::new("merge_with_int", format!("{}_{}", size, int_size)),
                        &(size, int_size),
                        |b: &mut criterion::Bencher, param_ref: &(usize, usize)| {
                            let (size_param, int_size_param) = *param_ref;
                            $closure(b, (size_param, int_size_param))
                        },
                    );
                }
            }

            group.finish();
        }
    };
}

// Creates a benchmark for hash merge many operations
#[macro_export]
macro_rules! benchmark_hash_merge_many {
    ($func_name:ident, $hasher_name:literal, $digest_counts:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-merge-many"));
            group.sample_size(10);

            for digest_count_ref in $digest_counts {
                let digest_count = *digest_count_ref;
                group.bench_with_input(
                    BenchmarkId::new("merge_many", digest_count),
                    &digest_count,
                    |b: &mut criterion::Bencher, &digest_count_param: &usize| {
                        $closure(b, digest_count_param)
                    },
                );
            }

            group.finish();
        }
    };
}

// Creates a benchmark for random coin operations
//
// # Usage
// ```no_run
// benchmark_rand_core!(
//     rpo_draw_elements,
//     RpoRandomCoin,
//     TEST_SEED,
//     "draw_element",
//     PRNG_OUTPUT_SIZES,
//     |b, coin, count| {
//         for _ in 0..count {
//             coin.draw_element();
//         }
//     }
// );
// ```
#[macro_export]
macro_rules! benchmark_rand_core {
    (
        $func_name:ident,
        $coin_type:ty,
        $seed:expr,
        $group_name:expr,
        $operation:literal,
        $sizes:expr,
        $closure:expr
    ) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            group.measurement_time($crate::common::config::DEFAULT_MEASUREMENT_TIME);
            group.sample_size($crate::common::config::DEFAULT_SAMPLE_SIZE);

            let mut coin = <$coin_type>::new($seed);

            for count_ref in $sizes {
                let count = *count_ref;
                group.bench_with_input(
                    BenchmarkId::new($operation, count),
                    &count,
                    |b: &mut criterion::Bencher, &count_param: &usize| {
                        $closure(b, &mut coin, count_param)
                    },
                );

                group.throughput(criterion::Throughput::Elements(count as u64));
            }

            group.finish();
        }
    };
}

// Creates a benchmark for random coin operations (legacy interface)
//
// # Usage
// ```no_run
// benchmark_rand_coin!(
//     rpo_draw_elements,
//     RpoRandomCoin,
//     TEST_SEED,
//     "draw_element",
//     PRNG_OUTPUT_SIZES,
//     |b, coin, count| {
//         for _ in 0..count {
//             coin.draw_element();
//         }
//     }
// );
// ```
#[macro_export]
macro_rules! benchmark_rand_coin {
    (
        $func_name:ident, $coin_type:ty, $seed:expr, $operation:literal, $sizes:expr, $closure:expr
    ) => {
        $crate::benchmark_rand_core! {
            $func_name,
            $coin_type,
            $seed,
            "rand-".to_string() + stringify!($coin_type).to_lowercase().as_str() + "-" + $operation,
            $operation,
            $sizes,
            $closure
        }
    };
}

// Creates a benchmark for word conversion operations
//
// # Usage
// ```no_run
// benchmark_word_convert!(convert_bool, bool, TEST_WORDS, |word| { word.try_into() });
// ```
#[macro_export]
macro_rules! benchmark_word_convert {
    ($func_name:ident, $target_type:ty, $test_data:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("word-convert-", stringify!($target_type)));

            group.bench_function(concat!("try_from_to_", stringify!($target_type)), |b| {
                b.iter(|| {
                    for word in $test_data {
                        let _result: Result<$target_type, _> = $closure(word);
                    }
                })
            });

            group.finish();
        }
    };
}

// Creates a benchmark with multiple test cases
//
// # Usage
// ```no_run
// benchmark_multi!(my_bench, "operation", &[1, 2, 3], |b, &value| {
//     // benchmark logic with value
// });
// ```
#[macro_export]
macro_rules! benchmark_multi {
    ($func_name:ident, $operation:literal, $test_cases:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("bench-", $operation));

            for &$test_case in $test_cases {
                group.bench_with_input(
                    BenchmarkId::new($operation, stringify!($test_case)),
                    &$test_case,
                    |b, test_case| $closure(b, test_case),
                );
            }

            group.finish();
        }
    };
}

// Creates a benchmark with setup and teardown that uses setup data
//
// # Usage
// ```no_run
// benchmark_with_setup_data!(my_bench, measurement_time, sample_size, group_name, setup_closure, |b, data| { ... });
// ```
#[macro_export]
macro_rules! benchmark_with_setup_data {
    (
        $func_name:ident,
        $measurement_time:expr,
        $sample_size:expr,
        $group_name:literal,
        $setup:expr,
        $closure:expr
    ) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            group.measurement_time($measurement_time);
            group.sample_size($sample_size as usize);

            let setup_data = $setup();

            group.bench_function("benchmark", |b| $closure(b, &setup_data));

            group.finish();
        }
    };
    (
        $func_name:ident,
        $measurement_time:expr,
        $sample_size:expr,
        $group_name:literal,
        $setup:expr,
        $closure:expr,
    ) => {
        benchmark_with_setup_data!(
            $func_name,
            $measurement_time,
            $sample_size,
            $group_name,
            $setup,
            $closure
        );
    };
}

// Creates a benchmark with setup but ignores setup data
//
// # Usage
// ```no_run
// benchmark_with_setup!(my_bench, measurement_time, sample_size, group_name, setup_closure, |b| { ... });
// ```
#[macro_export]
macro_rules! benchmark_with_setup {
    (
        $func_name:ident,
        $measurement_time:expr,
        $sample_size:expr,
        $group_name:literal,
        $setup:expr,
        $closure:expr
    ) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            group.measurement_time($measurement_time);
            group.sample_size($sample_size as usize);

            let _setup_data = $setup();

            group.bench_function("benchmark", |b| $closure(b));

            group.finish();
        }
    };
    (
        $func_name:ident,
        $measurement_time:expr,
        $sample_size:expr,
        $group_name:literal,
        $setup:expr,
        $closure:expr,
    ) => {
        benchmark_with_setup!(
            $func_name,
            $measurement_time,
            $sample_size,
            $group_name,
            $setup,
            $closure
        );
    };
}

// Creates a benchmark that uses setup data but doesn't pass it to the closure
//
// # Usage
// ```no_run
// benchmark_with_setup_custom!(my_bench, measurement_time, sample_size, group_name, setup_closure, |b, setup_data| { ... });
// ```
#[macro_export]
macro_rules! benchmark_with_setup_custom {
    (
        $func_name:ident,
        $measurement_time:expr,
        $sample_size:expr,
        $group_name:literal,
        $setup:expr,
        $closure:expr
    ) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            group.measurement_time($measurement_time);
            group.sample_size($sample_size as usize);

            let setup_data = $setup();

            group.bench_function("benchmark", |b| $closure(b, &setup_data));

            group.finish();
        }
    };
    (
        $func_name:ident,
        $measurement_time:expr,
        $sample_size:expr,
        $group_name:literal,
        $setup:expr,
        $closure:expr,
    ) => {
        benchmark_with_setup_custom!(
            $func_name,
            $measurement_time,
            $sample_size,
            $group_name,
            $setup,
            $closure
        );
    };
}

// Creates a benchmark for batch operations
//
// # Usage
// ```no_run
// benchmark_batch!(
//     batch_operation,
//     SIZES,
//     |b, size| {
//         // batch logic with size
//     },
//     |size| Some(criterion::Throughput::Elements(size as u64))
// );
// ```
#[macro_export]
macro_rules! benchmark_batch {
    ($func_name:ident, $sizes:expr, $closure:expr, $throughput:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("batch-", stringify!($func_name)));
            group.measurement_time($crate::common::config::DEFAULT_MEASUREMENT_TIME);
            group.sample_size($crate::common::config::DEFAULT_SAMPLE_SIZE);

            for size_ref in $sizes {
                let size = *size_ref;
                group.bench_with_input(BenchmarkId::new("batch", size), &size, |b, &size| {
                    $closure(b, size)
                });

                let throughput = $throughput(size);
                if let Some(ref t) = throughput {
                    group.throughput(t.clone());
                }
            }

            group.finish();
        }
    };
}

// Creates a benchmark for random coin initialization
//
// # Usage
// ```no_run
// benchmark_rand_new!(rand_rpo_new, RpoRandomCoin, TEST_SEED);
// ```
#[macro_export]
macro_rules! benchmark_rand_new {
    ($func_name:ident, $coin_type:ty, $seed:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group("rand-new");
            group.measurement_time($crate::common::config::DEFAULT_MEASUREMENT_TIME);
            group.sample_size($crate::common::config::DEFAULT_SAMPLE_SIZE);

            group.bench_function("new_from_word", |b| {
                b.iter(|| {
                    let _coin = <$coin_type>::new(black_box($seed));
                });
            });

            group.finish();
        }
    };
}

// Creates a benchmark for random coin drawing operations
//
// # Usage
// ```no_run
// benchmark_rand_draw!(
//     rand_rpo_draw_elements,
//     RpoRandomCoin,
//     TEST_SEED,
//     "draw_element",
//     PRNG_OUTPUT_SIZES,
//     |b, coin, count| {
//         for _ in 0..count {
//             let _element = coin.draw_element();
//         }
//     }
// );
// ```
#[macro_export]
macro_rules! benchmark_rand_draw {
    (
        $func_name:ident, $coin_type:ty, $seed:expr, $operation:literal, $sizes:expr, $closure:expr
    ) => {
        $crate::benchmark_rand_core! {
            $func_name,
            $coin_type,
            $seed,
            "rand-draw",
            $operation,
            $sizes,
            $closure
        }
    };
}

// Creates a benchmark for random coin reseeding operations
//
// # Usage
// ```no_run
// benchmark_rand_reseed!(rand_rpo_reseed, RpoRandomCoin, TEST_SEED);
// ```
#[macro_export]
macro_rules! benchmark_rand_reseed {
    ($func_name:ident, $coin_type:ty, $seed:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group("rand-reseed");
            group.measurement_time($crate::common::config::DEFAULT_MEASUREMENT_TIME);
            group.sample_size($crate::common::config::DEFAULT_SAMPLE_SIZE);

            let mut coin = <$coin_type>::new($seed);
            let new_seeds: Vec<miden_crypto::Word> = (0..10)
                .map(|i| miden_crypto::Word::new([miden_crypto::Felt::new((i + 1) as u64); 4]))
                .collect();

            group.bench_function("reseed", |b| {
                b.iter(|| {
                    for seed in &new_seeds {
                        coin.reseed(black_box(*seed));
                    }
                });
            });

            group.finish();
        }
    };
}

/// Creates a benchmark for random coin integer drawing operations
///
/// # Usage
/// ```no_run
/// benchmark_rand_draw_integers!(rand_rpo_draw_integers, RpoRandomCoin, TEST_SEED);
/// ```
#[macro_export]
macro_rules! benchmark_rand_draw_integers {
    ($func_name:ident, $coin_type:ty, $seed:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group("rand-draw-integers");
            group.measurement_time($crate::common::config::DEFAULT_MEASUREMENT_TIME);
            group.sample_size($crate::common::config::DEFAULT_SAMPLE_SIZE);

            let mut coin = <$coin_type>::new($seed);

            let num_values_list = &[1, 10, 100];
            let domain_sizes = &[256, 1024, 4096, 65536];

            for &num_values in num_values_list {
                for &domain_size in domain_sizes {
                    // Ensure num_values < domain_size to avoid assertion error
                    if num_values < domain_size {
                        group.bench_with_input(
                            BenchmarkId::new(
                                "draw_integers",
                                format!("{}_{}", num_values, domain_size),
                            ),
                            &(num_values, domain_size),
                            |b, &(num_values, domain_size)| {
                                b.iter(|| {
                                    let _result = coin
                                        .draw_integers(
                                            black_box(num_values),
                                            black_box(domain_size),
                                            black_box(0),
                                        )
                                        .unwrap();
                                })
                            },
                        );
                    }
                }
            }

            group.finish();
        }
    };
}

/// Creates a benchmark for random coin leading zero checking
///
/// # Usage
/// ```no_run
/// benchmark_rand_check_leading_zeros!(rand_rpo_check_leading_zeros, RpoRandomCoin, TEST_SEED);
/// ```
#[macro_export]
macro_rules! benchmark_rand_check_leading_zeros {
    ($func_name:ident, $coin_type:ty, $seed:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group("rand-check-leading-zeros");
            group.measurement_time($crate::common::config::DEFAULT_MEASUREMENT_TIME);
            group.sample_size($crate::common::config::DEFAULT_SAMPLE_SIZE);

            let coin = <$coin_type>::new($seed);
            let test_values: Vec<u64> = (0..100).map(|i| i as u64).collect();

            group.bench_function("check_leading_zeros", |b| {
                b.iter(|| {
                    for &value in &test_values {
                        let _zeros = coin.check_leading_zeros(black_box(value));
                    }
                });
            });

            group.finish();
        }
    };
}

/// Creates a benchmark for random coin byte filling operations
///
/// # Usage
/// ```no_run
/// benchmark_rand_fill_bytes!(
///     rand_rpo_fill_bytes,
///     RpoRandomCoin,
///     TEST_SEED,
///     &[1, 32, 64, 128, 256, 512, 1024]
/// );
/// ```
#[macro_export]
macro_rules! benchmark_rand_fill_bytes {
    ($func_name:ident, $coin_type:ty, $seed:expr, $sizes:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group("rand-fill-bytes");
            group.measurement_time($crate::common::config::DEFAULT_MEASUREMENT_TIME);
            group.sample_size($crate::common::config::DEFAULT_SAMPLE_SIZE);

            let mut coin = <$coin_type>::new($seed);

            for &size in $sizes {
                group.bench_with_input(BenchmarkId::new("fill_bytes", size), &size, |b, &size| {
                    let mut buffer = vec![0u8; size];
                    b.iter(|| {
                        coin.fill_bytes(black_box(&mut buffer));
                    })
                });
            }

            group.finish();
        }
    };
}
