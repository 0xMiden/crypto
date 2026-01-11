# Miden Crypto Documentation

This directory contains the source files for the Miden Crypto documentation, built with MkDocs Material.

## Building the Documentation

### Prerequisites

Install MkDocs and the Material theme:

```bash
pip install mkdocs-material mkdocstrings[python]
```

### Building Locally

To build and serve the documentation locally:

```bash
mkdocs serve
```

The documentation will be available at `http://127.0.0.1:8000`.

### Building for Production

To build static HTML files:

```bash
mkdocs build
```

The output will be in the `site/` directory.

## Documentation Structure

The documentation is organized by module:

- **Getting Started**: Installation and basic usage
- **Hash Functions**: All available hash functions
- **Merkle Trees**: Tree data structures
- **Digital Signatures**: Signature schemes
- **Encryption**: AEAD encryption schemes
- **Key Exchange**: ECDH and IES
- **Random Number Generation**: Pseudo-random generators
- **Core Types**: Field elements and words
- **STARK Proving System**: STARK-related components

## Contributing

When adding or updating documentation:

1. Update the relevant markdown files in this directory
2. Update `mkdocs.yml` if adding new pages
3. Test locally with `mkdocs serve`
4. Ensure all links work correctly

