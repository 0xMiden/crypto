//! Basic usage example for miden-serialization

use miden_serialization::{ByteRead, ByteWrite, Deserializable, Serializable};

#[derive(Debug, PartialEq)]
struct Point {
    x: u32,
    y: u32,
}

impl Serializable for Point {
    fn write_into<W: ByteWrite + ?Sized>(&self, target: &mut W) -> Result<(), W::Error> {
        self.x.write_into(target)?;
        self.y.write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u32>() * 2
    }
}

impl Deserializable for Point {
    fn read_from<R: ByteRead>(source: &mut R) -> Result<Self, R::Error> {
        Ok(Point {
            x: u32::read_from(source)?,
            y: u32::read_from(source)?,
        })
    }
}

fn main() {
    // Serialize a point
    let point = Point { x: 10, y: 20 };
    let bytes = point.to_bytes();

    println!("Serialized point: {:?}", bytes);
    println!("Size: {} bytes", bytes.len());

    // Deserialize back
    let decoded = Point::read_from_bytes(&bytes).unwrap();

    println!("Decoded point: {:?}", decoded);
    assert_eq!(point, decoded);

    // Works with collections too
    let points = vec![
        Point { x: 1, y: 2 },
        Point { x: 3, y: 4 },
        Point { x: 5, y: 6 },
    ];

    let bytes = points.to_bytes();
    let decoded_points = Vec::<Point>::read_from_bytes(&bytes).unwrap();

    println!("\nSerialized {} points", decoded_points.len());
    for (i, p) in decoded_points.iter().enumerate() {
        println!("  Point {}: ({}, {})", i, p.x, p.y);
    }
}
