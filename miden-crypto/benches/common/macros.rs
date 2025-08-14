//! Benchmark macros to reduce boilerplate code
//! 
//! This module provides procedural macros to eliminate repetitive 
//! patterns commonly found in benchmark code.


/// Creates a standard benchmark group with common configuration
/// 
/// # Usage
/// ```rust
/// benchmark_group!(my_group_name, "display-name", measurement_time, sample_size);
/// ```
#[macro_export]
macro_rules! benchmark_group {
    ($func_name:ident, $group_name:literal, $measurement_time:expr, $sample_size:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            group.measurement_time($measurement_time);
            group.sample_size($sample_size as usize);
        }
    };
    ($func_name:ident, $group_name:literal) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            group.measurement_time(crate::common::config::DEFAULT_MEASUREMENT_TIME);
            group.sample_size(crate::common::config::DEFAULT_SAMPLE_SIZE as usize);
        }
    };
}

/// Creates a simple benchmark function that iterates over a collection
/// 
/// # Usage
/// ```rust
/// benchmark_simple!(my_bench, "bench-name", &my_collection, |b, item| {
///     // benchmark logic here
/// });
/// ```
#[macro_export]
macro_rules! benchmark_simple {
    ($func_name:ident, $bench_name:literal, $data:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(stringify!($func_name).replace("fn ", ""));
            
            group.bench_function($bench_name, |b| {
                $closure(b, $data)
            });
            
            group.finish();
        }
    }
}

/// Creates a parameterized benchmark that iterates over input sizes
/// 
/// # Usage
/// ```rust
/// benchmark_sizes!(my_bench, "operation", &size_array, |b, &size| {
///     // benchmark logic with size
/// });
/// ```
#[macro_export]
macro_rules! benchmark_sizes {
    ($func_name:ident, $operation:literal, $sizes:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            benchmark_group!($func_name, concat!("bench-", $operation));
            
            for &$size in $sizes {
                group.bench_with_input(
                    BenchmarkId::new($operation, $size),
                    &$size,
                    |b, &$size| {
                        $closure(b, $size)
                    },
                );
                
                // Common throughput calculations
                if $size > 0 {
                    group.throughput(criterion::Throughput::Elements($size as u64));
                }
            }
            
            group.finish();
        }
    };
}

/// Creates a benchmark for hash algorithms with common patterns
/// 
/// # Usage
/// ```rust
/// benchmark_hash!(hash_rpo256_single, "rpo256", "single", HASH_INPUT_SIZES, |b, size: usize| {
///     let data = if size <= 64 {
///         generate_byte_array_sequential(size)
///     } else {
///         generate_byte_array_random(size)
///     };
///     b.iter(|| Rpo256::hash(black_box(&data)))
/// }, size, Some(criterion::Throughput::Bytes(size as u64)));
/// ```
#[macro_export]
macro_rules! benchmark_hash {
    ($func_name:ident, $hasher_name:literal, $operation:literal, $sizes:expr, $closure:expr, $size_var:ident, $throughput:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-", $operation));
            group.sample_size(10); // Minimum required by Criterion
            
            for size_ref in $sizes {
                let size_val = *size_ref;
                group.bench_with_input(
                    BenchmarkId::new($operation, size_val),
                    &size_val,
                    |b: &mut criterion::Bencher, &size_param: &usize| {
                        $closure(b, size_param)
                    },
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
    ($func_name:ident, $hasher_name:literal, $operation:literal, $sizes:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-", $operation));
            group.sample_size(10); // Minimum required by Criterion
            
            for size_ref in $sizes {
                let size = *size_ref;
                group.bench_with_input(
                    BenchmarkId::new($operation, size),
                    &size,
                    |b: &mut criterion::Bencher, &size_param: &usize| {
                        $closure(b, size_param)
                    },
                );
                
                if size > 0 {
                    group.throughput(criterion::Throughput::Bytes(size as u64));
                }
            }
            
            group.finish();
        }
    };
}

/// Creates a benchmark for hash merge operations
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
                    |b: &mut criterion::Bencher, &size_param: &usize| {
                        $closure(b, size_param)
                    },
                );
            }
            
            group.finish();
        }
    };
}

/// Creates a benchmark for hash felt operations
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
                    |b: &mut criterion::Bencher, &count_param: &usize| {
                        $closure(b, count_param)
                    },
                );
                
                let throughput_result = $throughput(count);
                if let Some(ref t) = throughput_result {
                    group.throughput(t.clone());
                }
            }
            
            group.finish();
        }
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

/// Creates a benchmark for random coin operations
/// 
/// # Usage
/// ```rust
/// benchmark_rand_coin!(rpo_draw_elements, RpoRandomCoin, TEST_SEED, "draw_element", PRNG_OUTPUT_SIZES, |b, coin, count| {
///     for _ in 0..count {
///         coin.draw_element();
///     }
/// });
/// ```
#[macro_export]
macro_rules! benchmark_rand_coin {
    ($func_name:ident, $coin_type:ty, $seed:expr, $operation:literal, $sizes:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group("rand-".to_string() + stringify!($coin_type).to_lowercase().as_str() + "-" + $operation);
            
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

/// Creates a benchmark for word conversion operations
/// 
/// # Usage
/// ```rust
/// benchmark_word_convert!(convert_bool, bool, TEST_WORDS, |word| {
///     word.try_into()
/// });
/// ```
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

/// Creates a benchmark group configuration
/// 
/// # Usage
/// ```rust
/// benchmark_group!(
///     my_benchmark_group,
///     func1,
///     func2,
///     func3,
/// );
/// ```
#[macro_export]
macro_rules! benchmark_group_config {
    ($group_name:ident, $($func:ident),*) => {
        criterion_group!(
            $group_name,
            $($func),*
        );
    };
}

/// Creates the main benchmark entry point
/// 
/// # Usage
/// ```rust
/// benchmark_main!(my_benchmark_group);
/// ```
#[macro_export]
macro_rules! benchmark_main {
    ($group_name:ident) => {
        criterion_main!($group_name);
    };
}

/// Creates a benchmark with multiple test cases
/// 
/// # Usage
/// ```rust
/// benchmark_multi!(my_bench, "operation", &[1, 2, 3], |b, &value| {
///     // benchmark logic with value
/// });
/// ```
#[macro_export]
macro_rules! benchmark_multi {
    ($func_name:ident, $operation:literal, $test_cases:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("bench-", $operation));
            
            for &$test_case in $test_cases {
                group.bench_with_input(
                    BenchmarkId::new($operation, stringify!($test_case)),
                    &$test_case,
                    |b, test_case| {
                        $closure(b, test_case)
                    },
                );
            }
            
            group.finish();
        }
    };
}

/// Creates a benchmark with setup and teardown that uses setup data
/// 
/// # Usage
/// ```rust
/// benchmark_with_setup_data!(my_bench, measurement_time, sample_size, group_name, setup_closure, |b, data| { ... });
/// ```
#[macro_export]
macro_rules! benchmark_with_setup_data {
    ($func_name:ident, $measurement_time:expr, $sample_size:expr, $group_name:literal, $setup:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            group.measurement_time($measurement_time);
            group.sample_size($sample_size as usize);
            
            let setup_data = $setup();
            
            group.bench_function("benchmark", |b| {
                $closure(b, &setup_data)
            });
            
            group.finish();
        }
    };
    ($func_name:ident, $measurement_time:expr, $sample_size:expr, $group_name:literal, $setup:expr, $closure:expr,) => {
        benchmark_with_setup_data!($func_name, $measurement_time, $sample_size, $group_name, $setup, $closure);
    };
}

/// Creates a benchmark with setup but ignores setup data
/// 
/// # Usage
/// ```rust
/// benchmark_with_setup!(my_bench, measurement_time, sample_size, group_name, setup_closure, |b| { ... });
/// ```
#[macro_export]
macro_rules! benchmark_with_setup {
    ($func_name:ident, $measurement_time:expr, $sample_size:expr, $group_name:literal, $setup:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            group.measurement_time($measurement_time);
            group.sample_size($sample_size as usize);
            
            let _setup_data = $setup();
            
            group.bench_function("benchmark", |b| { $closure(b) });
            
            group.finish();
        }
    };
    ($func_name:ident, $measurement_time:expr, $sample_size:expr, $group_name:literal, $setup:expr, $closure:expr,) => {
        benchmark_with_setup!($func_name, $measurement_time, $sample_size, $group_name, $setup, $closure);
    };
}

/// Creates a benchmark that uses setup data but doesn't pass it to the closure
/// 
/// # Usage
/// ```rust
/// benchmark_with_setup_custom!(my_bench, measurement_time, sample_size, group_name, setup_closure, |b, setup_data| { ... });
/// ```
#[macro_export]
macro_rules! benchmark_with_setup_custom {
    ($func_name:ident, $measurement_time:expr, $sample_size:expr, $group_name:literal, $setup:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            group.measurement_time($measurement_time);
            group.sample_size($sample_size as usize);
            
            let setup_data = $setup();
            
            group.bench_function("benchmark", |b| { $closure(b, &setup_data) });
            
            group.finish();
        }
    };
    ($func_name:ident, $measurement_time:expr, $sample_size:expr, $group_name:literal, $setup:expr, $closure:expr,) => {
        benchmark_with_setup_custom!($func_name, $measurement_time, $sample_size, $group_name, $setup, $closure);
    };
}

/// Creates a benchmark for batch operations
/// 
/// # Usage
/// ```rust
/// benchmark_batch!(batch_operation, SIZES, |b, size| {
///     // batch logic with size
/// }, |size| Some(criterion::Throughput::Elements(size as u64)));
/// ```
#[macro_export]
macro_rules! benchmark_batch {
    ($func_name:ident, $sizes:expr, $closure:expr, $throughput:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("batch-", stringify!($func_name)));
            group.measurement_time(crate::common::config::DEFAULT_MEASUREMENT_TIME);
            group.sample_size(crate::common::config::DEFAULT_SAMPLE_SIZE as usize);
            
            for size_ref in $sizes {
                let size = *size_ref;
                group.bench_with_input(
                    BenchmarkId::new("batch", size),
                    &size,
                    |b, &size| {
                        $closure(b, size)
                    },
                );
                
                let throughput = $throughput(size);
                if let Some(ref t) = throughput {
                    group.throughput(t.clone());
                }
            }
            
            group.finish();
        }
    };
}