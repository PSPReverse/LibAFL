//! Loader for the librarian's mailbox catalog (JSON). The real catalog is AMD-derived and local-only:
//! never commit it; load it at runtime from a path given in the yaml. Only the fields below are used.
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct Field {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default)]
    pub ty: String,
    #[serde(default)]
    pub offset: Option<serde_json::Value>,
}

impl Field {
    /// byte offset, if the catalog gives a number
    pub fn offset(&self) -> Option<usize> {
        self.offset.as_ref().and_then(|v| v.as_u64()).map(|v| v as usize)
    }

    /// width of a scalar field (u8/u16/u32/u64, tolerating suffixes like "u32?" or "u8 (bits 7:0)")
    pub fn scalar_width(&self) -> Option<usize> {
        let t = self.ty.trim();
        [("u64", 8), ("u32", 4), ("u16", 2), ("u8", 1)]
            .iter()
            .find(|(p, _)| t.starts_with(p))
            .map(|&(_, w)| w)
    }

    /// size in bytes for structs written "struct(80 B)" / "struct(12 B?)"
    pub fn struct_size(&self) -> Option<usize> {
        let t = self.ty.trim().strip_prefix("struct(")?;
        t.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
    }

    /// (offset, width) for fields the mutators can treat as typed scalars
    pub fn scalar(&self) -> Option<(usize, usize)> {
        Some((self.offset()?, self.scalar_width()?))
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Command {
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub arg_layout: Vec<Field>,
    #[serde(default)]
    pub maps_buffer: Option<bool>,
    /// total argument size in bytes when the catalog states one
    #[serde(default)]
    pub arg_size: Option<serde_json::Value>,
}

impl Command {
    /// Buffer length to allocate: stated arg_size if numeric, else the end of the last field, min header 8.
    pub fn buf_len(&self) -> usize {
        let from_fields = self
            .arg_layout
            .iter()
            .filter_map(|f| Some(f.offset()? + f.scalar_width().or(f.struct_size())?))
            .max()
            .unwrap_or(8);
        let stated = self.arg_size.as_ref().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        stated.max(from_fields).max(8)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Catalog {
    pub commands: Vec<Command>,
}

impl Catalog {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
    pub fn command(&self, id: u32) -> Option<&Command> {
        self.commands.iter().find(|c| c.id == id)
    }
}
