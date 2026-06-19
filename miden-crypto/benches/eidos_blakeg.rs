use std::{array, hint::black_box};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use miden_crypto::hash::eidos::bench::{
    NATIVE_LANES, compress, compress_packed_native, compress_packed_native_raw_xof,
    compress_raw_xof, matrix_finalize, matrix_finalize_packed_native,
};

fn scalar_cv() -> [u32; 8] {
    array::from_fn(|i| 0x243f_6a88u32.wrapping_add((i as u32).wrapping_mul(0x9e37_79b9)))
}

fn scalar_block() -> [u32; 16] {
    array::from_fn(|i| 0x1319_8a2eu32.wrapping_add((i as u32).wrapping_mul(0x85eb_ca6b)))
}

fn scalar_xof() -> [u32; 16] {
    compress_raw_xof(scalar_cv(), scalar_block())
}

fn packed_cv() -> [[u32; NATIVE_LANES]; 8] {
    array::from_fn(|word| {
        array::from_fn(|lane| {
            0x243f_6a88u32
                .wrapping_add((word as u32).wrapping_mul(0x9e37_79b9))
                .wrapping_add((lane as u32).wrapping_mul(0x7f4a_7c15))
        })
    })
}

fn packed_block() -> [[u32; NATIVE_LANES]; 16] {
    array::from_fn(|word| {
        array::from_fn(|lane| {
            0x1319_8a2eu32
                .wrapping_add((word as u32).wrapping_mul(0x85eb_ca6b))
                .wrapping_add((lane as u32).wrapping_mul(0xc2b2_ae35))
        })
    })
}

fn packed_xof() -> [[u32; NATIVE_LANES]; 16] {
    compress_packed_native_raw_xof(packed_cv(), packed_block())
}

fn bench_blakeg_layers(c: &mut Criterion) {
    let mut group = c.benchmark_group("eidos_blakeg_layers");

    group.throughput(Throughput::Elements(1));
    group.bench_function("scalar/raw_xof", |b| {
        let cv = scalar_cv();
        let block = scalar_block();
        b.iter(|| compress_raw_xof(black_box(cv), black_box(block)));
    });
    group.bench_function("scalar/matrix_finalizer", |b| {
        let input = scalar_xof();
        b.iter(|| matrix_finalize(black_box(input)));
    });
    group.bench_function("scalar/compress", |b| {
        let cv = scalar_cv();
        let block = scalar_block();
        b.iter(|| compress(black_box(cv), black_box(block)));
    });

    group.throughput(Throughput::Elements(NATIVE_LANES as u64));
    group.bench_function("packed_native/raw_xof", |b| {
        let cv = packed_cv();
        let block = packed_block();
        b.iter(|| compress_packed_native_raw_xof(black_box(cv), black_box(block)));
    });
    group.bench_function("packed_native/matrix_finalizer", |b| {
        let input = packed_xof();
        b.iter(|| matrix_finalize_packed_native(black_box(input)));
    });
    group.bench_function("packed_native/compress", |b| {
        let cv = packed_cv();
        let block = packed_block();
        b.iter(|| compress_packed_native(black_box(cv), black_box(block)));
    });

    group.finish();
}

criterion_group!(eidos_blakeg_benches, bench_blakeg_layers);
criterion_main!(eidos_blakeg_benches);
