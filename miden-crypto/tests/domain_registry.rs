use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

const REGISTRY: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/registry/poseidon2-domains.toml"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TableKind {
    Range,
    Domain,
}

#[derive(Debug)]
struct Table {
    kind: TableKind,
    fields: BTreeMap<String, String>,
}

#[derive(Debug)]
struct Range {
    name: String,
    maintainer: String,
    start: u32,
    end: u32,
}

#[derive(Debug)]
struct Domain {
    name: String,
    maintainer: String,
    domain_id: u32,
    version: u8,
    payload_kind: String,
    fields: BTreeMap<String, String>,
}

impl Domain {
    fn selector(&self) -> u32 {
        (self.domain_id << 8) | u32::from(self.version)
    }
}

#[test]
fn poseidon2_domain_registry_is_well_formed() {
    let tables = parse_registry(REGISTRY);
    let ranges = parse_ranges(&tables);
    let domains = parse_domains(&tables);

    assert!(!ranges.is_empty(), "registry must define at least one range");
    assert!(!domains.is_empty(), "registry must define at least one domain");

    assert_ranges_are_sorted_and_disjoint(&ranges);
    assert_domains_are_sorted(&domains);
    assert_domains_are_unique(&domains);
    assert_domains_are_in_declared_ranges(&domains, &ranges);
    assert_domain_payload_kinds_are_known(&domains);
    assert_domain_fields_are_complete(&domains);
}

fn parse_registry(input: &str) -> Vec<Table> {
    let mut tables = Vec::new();
    let mut current_kind: Option<TableKind> = None;
    let mut current_fields = BTreeMap::new();

    for (line_no, raw_line) in input.lines().enumerate() {
        let line_no = line_no + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match line {
            "[[ranges]]" => {
                push_table(&mut tables, &mut current_kind, &mut current_fields);
                current_kind = Some(TableKind::Range);
            },
            "[[domains]]" => {
                push_table(&mut tables, &mut current_kind, &mut current_fields);
                current_kind = Some(TableKind::Domain);
            },
            _ => {
                let (key, value) = line
                    .split_once('=')
                    .unwrap_or_else(|| panic!("line {line_no}: expected key = value"));
                let key = key.trim();
                let value = value.trim();
                assert!(!key.is_empty(), "line {line_no}: empty key");
                assert!(
                    current_kind.is_some(),
                    "line {line_no}: key/value appeared before a table header"
                );
                assert!(
                    current_fields.insert(key.to_string(), value.to_string()).is_none(),
                    "line {line_no}: duplicate key `{key}`"
                );
            },
        }
    }

    push_table(&mut tables, &mut current_kind, &mut current_fields);
    tables
}

fn push_table(
    tables: &mut Vec<Table>,
    current_kind: &mut Option<TableKind>,
    current_fields: &mut BTreeMap<String, String>,
) {
    if let Some(kind) = current_kind.take() {
        tables.push(Table {
            kind,
            fields: std::mem::take(current_fields),
        });
    }
}

fn parse_ranges(tables: &[Table]) -> Vec<Range> {
    tables
        .iter()
        .filter(|table| table.kind == TableKind::Range)
        .map(|table| {
            assert_expected_keys(table, &["name", "maintainer", "start", "end", "description"]);
            let name = required_string(table, "name");
            let maintainer = required_string(table, "maintainer");
            let start = required_u32(table, "start");
            let end = required_u32(table, "end");
            let _description = required_string(table, "description");
            assert!(start <= end, "range `{name}` has start > end");
            assert!(start != 0, "range `{name}` includes reserved domain_id 0");
            assert!(end < (1 << 24), "range `{name}` exceeds 24-bit id range");
            Range { name, maintainer, start, end }
        })
        .collect()
}

fn parse_domains(tables: &[Table]) -> Vec<Domain> {
    tables
        .iter()
        .filter(|table| table.kind == TableKind::Domain)
        .map(|table| {
            assert_expected_keys(
                table,
                &[
                    "name",
                    "maintainer",
                    "domain_id",
                    "version",
                    "status",
                    "payload_kind",
                    "frame",
                    "param0",
                    "param1",
                    "rate",
                ],
            );
            let name = required_string(table, "name");
            let maintainer = required_string(table, "maintainer");
            let domain_id = required_u32(table, "domain_id");
            let version = required_u8(table, "version");
            let payload_kind = required_string(table, "payload_kind");
            Domain {
                name,
                maintainer,
                domain_id,
                version,
                payload_kind,
                fields: table.fields.clone(),
            }
        })
        .collect()
}

fn assert_ranges_are_sorted_and_disjoint(ranges: &[Range]) {
    let mut previous_end = None;
    let mut names = BTreeSet::new();
    for range in ranges {
        assert!(names.insert(&range.name), "duplicate range name `{}`", range.name);
        if let Some(previous_end) = previous_end {
            assert!(range.start > previous_end, "range `{}` overlaps or is not sorted", range.name);
        }
        previous_end = Some(range.end);
    }
}

fn assert_domains_are_sorted(domains: &[Domain]) {
    for pair in domains.windows(2) {
        let prev = &pair[0];
        let next = &pair[1];
        assert!(
            (prev.domain_id, prev.version) < (next.domain_id, next.version),
            "domain `{}` must appear before `{}` by (domain_id, version)",
            next.name,
            prev.name
        );
    }
}

fn assert_domains_are_unique(domains: &[Domain]) {
    let mut names = BTreeSet::new();
    let mut selectors = BTreeMap::new();

    for domain in domains {
        assert!(domain.domain_id != 0, "domain `{}` uses reserved domain_id 0", domain.name);
        assert!(domain.domain_id < (1 << 24), "domain `{}` exceeds 24-bit id range", domain.name);
        assert!(domain.version != 0, "domain `{}` uses reserved version 0", domain.name);
        assert!(names.insert(&domain.name), "duplicate domain name `{}`", domain.name);

        let selector = domain.selector();
        assert!(
            selectors.insert(selector, &domain.name).is_none(),
            "duplicate selector 0x{selector:08x}"
        );
    }
}

fn assert_domains_are_in_declared_ranges(domains: &[Domain], ranges: &[Range]) {
    for domain in domains {
        let containing_ranges = containing_ranges(domain, ranges);
        assert_eq!(
            containing_ranges.len(),
            1,
            "domain `{}` must belong to exactly one declared range",
            domain.name
        );

        let range = containing_ranges[0];
        assert_eq!(
            domain.maintainer, range.maintainer,
            "domain `{}` maintainer must match containing range `{}`",
            domain.name, range.name
        );
    }
}

fn containing_ranges<'a>(domain: &Domain, ranges: &'a [Range]) -> Vec<&'a Range> {
    ranges
        .iter()
        .filter(|range| range.start <= domain.domain_id && domain.domain_id <= range.end)
        .collect()
}

fn assert_domain_payload_kinds_are_known(domains: &[Domain]) {
    for domain in domains {
        match domain.payload_kind.as_str() {
            "fixed" | "felt_stream" | "byte_stream" | "custom" => {},
            other => panic!("domain `{}` has unknown payload_kind `{other}`", domain.name),
        }
    }
}

fn assert_domain_fields_are_complete(domains: &[Domain]) {
    for domain in domains {
        required_domain_string(domain, "status");
        required_domain_string(domain, "frame");
        required_domain_string(domain, "param0");
        required_domain_string(domain, "param1");
        required_domain_string(domain, "rate");
    }
}

fn required_domain_string(domain: &Domain, key: &str) -> String {
    let value = domain
        .fields
        .get(key)
        .unwrap_or_else(|| panic!("domain `{}` is missing `{key}`", domain.name));
    parse_string(value, key)
}

fn assert_expected_keys(table: &Table, expected: &[&str]) {
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    let actual: BTreeSet<&str> = table.fields.keys().map(String::as_str).collect();

    assert_eq!(
        actual, expected,
        "{table} has unexpected or missing fields; expected {expected:?}, got {actual:?}"
    );
}

fn required_string(table: &Table, key: &str) -> String {
    parse_string(required_value(table, key), key)
}

fn required_u8(table: &Table, key: &str) -> u8 {
    let value = required_u32(table, key);
    u8::try_from(value).unwrap_or_else(|_| panic!("`{key}` value {value} does not fit in u8"))
}

fn required_u32(table: &Table, key: &str) -> u32 {
    let value = required_value(table, key);
    parse_u32(value, key)
}

fn required_value<'a>(table: &'a Table, key: &str) -> &'a str {
    table
        .fields
        .get(key)
        .unwrap_or_else(|| panic!("{table}: missing `{key}`"))
        .as_str()
}

fn parse_string(value: &str, key: &str) -> String {
    let value = value.trim();
    assert!(
        value.starts_with('"') && value.ends_with('"') && value.len() >= 2,
        "`{key}` must be a quoted string"
    );
    let value = &value[1..value.len() - 1];
    assert!(!value.is_empty(), "`{key}` must not be empty");
    value.to_string()
}

fn parse_u32(value: &str, key: &str) -> u32 {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
            .unwrap_or_else(|err| panic!("`{key}` has invalid hex value `{value}`: {err}"))
    } else {
        value
            .parse()
            .unwrap_or_else(|err| panic!("`{key}` has invalid integer value `{value}`: {err}"))
    }
}

impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            TableKind::Range => write!(f, "[[ranges]]"),
            TableKind::Domain => write!(f, "[[domains]]"),
        }
    }
}
