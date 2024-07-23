use anyhow::Error;
use chrono::{DateTime, NaiveDate, Utc};
use core::ptr::addr_of_mut;
use core::{
    fmt,
    fmt::{Display, Formatter},
};
use once_cell::sync::Lazy;
use record::{Item, MetaDataType, Tag};
use regex::Regex;
use sanitize_filename_reader_friendly::sanitize;
use serde_json::{Result, Value};
use std::borrow::{Borrow, BorrowMut};
use std::collections::btree_map::Entry::{Occupied, Vacant};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, Read};
use std::os::windows::ffi::OsStringExt;
use std::{default, fs};
use walkdir::{DirEntry, WalkDir};

use std::collections::HashSet;

mod record {
    use std::{collections::HashSet, default};

    use chrono::{DateTime, Utc};

    #[derive(PartialEq, Eq, Copy, Clone, Default)]
    pub enum MetaDataType {
        #[default]
        None,
        Stem,
        Docspell,
    }

    #[derive(Hash, Eq, PartialEq, Debug, Clone)]
    pub struct Tag {
        pub name: String,
        pub category: String,
    }

    #[derive(Default, Eq, PartialEq, Clone)]
    pub struct Item {
        pub path: String,
        pub name: String,
        pub date: DateTime<Utc>,
        pub tags: HashSet<Tag>,
        pub metadata_type: MetaDataType,
    }
}

static mut RECORDS: BTreeMap<String, record::Item> = BTreeMap::new();

enum VersionControlSystem {
    Git,
    Svn,
}

enum DirectoryClassification {
    Regular,
    VersionControl(VersionControlSystem),
}

enum SpreadsheetFileType {
    Excel,
    Csv(char),
}

enum DocumentFileType {
    Pdf,
    Text,
    Word,
}

enum SecretFileType {
    Env,
}

enum ConfigurationFileType {
    Yaml,
    Json,
    Ini,
}

enum DatabaseFileType {
    Sqlite,
    Sql,
    Db,
    Pdb,
}

enum ArchiveFileType {
    Zip,
    Rar,
}

enum FileClassification {
    Regular,
    Secret(SecretFileType),
    Spreadsheet(SpreadsheetFileType),
    Document(DocumentFileType),
    Configuration(ConfigurationFileType),
    Database(DatabaseFileType),
    Archive(ArchiveFileType),
}

enum EntryClassification {
    File(FileClassification),
    Dir(DirectoryClassification),
}

trait OptionFlatStringExt {
    fn to_lowercase(&self) -> Option<String>;
}

impl OptionFlatStringExt for Option<&OsStr> {
    fn to_lowercase(&self) -> Option<String> {
        self.map(|x| x.to_string_lossy().to_ascii_lowercase())
    }
}

struct Platform {
    fs_dir_sep: char,
    sys_dir: String,
    user_dir: String,
    app_data: String,
    tmp_dir: String,
}

#[link(name = "secur32")]
extern "system" {
    fn GetUserNameW(buf: *mut u16, len: *mut u32) -> u32;
}

static PLATFORM: Lazy<Platform> = Lazy::new(|| unsafe {
    let mut buf = [0u16; 64];
    #[allow(clippy::cast_possible_truncation)]
    let mut len: u32 = buf.len() as u32;

    if GetUserNameW(buf.as_mut_ptr(), &mut len) == 0 {
        panic!("failed to get user name");
    }

    // ensure string is terminated
    buf[buf.len() - 1] = u16::default();

    let name = OsString::from_wide(&buf)
        .as_os_str()
        .to_string_lossy()
        .into_owned();

    Platform {
        fs_dir_sep: '\\',
        sys_dir: "C:\\Windows".into(),
        user_dir: format!("C:\\users\\{}", name),
        app_data: format!("C:\\users\\{}\\appdata", name),
        tmp_dir: format!("C:\\users\\{}\\appdata\\local\\temp", name),
    }
});

trait DirEntryExt {
    fn classify(&self) -> EntryClassification;
    fn classify_dir(&self) -> DirectoryClassification;
    fn classify_file(&self) -> FileClassification;
    fn is_allowed(&self) -> bool;
    fn is_blacklisted(&self) -> bool;
}

impl DirEntryExt for DirEntry {
    fn is_blacklisted(&self) -> bool {
        self.path()
            .file_name()
            .and_then(OsStr::to_str)
            .map(|path| path == PLATFORM.sys_dir || path == PLATFORM.tmp_dir)
            .unwrap_or(false)
    }

    fn is_allowed(&self) -> bool {
        !self.is_blacklisted()
    }

    fn classify_file(&self) -> FileClassification {
        let path = self.path();
        let file_name = path.file_name();
        let extension = path.extension();
        match file_name.to_lowercase().as_deref() {
            Some(".env") => FileClassification::Secret(SecretFileType::Env),
            Some(_) => match extension.to_lowercase().as_deref() {
                Some(
                    "xlw" | "xlr" | "xls" | "xlsl" | "xlsb" | "xltx" | "xltm" | "xlam" | "xla",
                ) => FileClassification::Spreadsheet(SpreadsheetFileType::Excel),
                Some("csv" | "prn") => {
                    let mut seps = [
                        (char::default(), 1usize),
                        (',', 0),
                        ('\t', 0),
                        (':', 0),
                        (';', 0),
                        ('|', 0),
                        (' ', 0),
                    ];

                    let csv_chars = fs::read_to_string(self.path()).unwrap_or_default();
                    for (sep, count) in &mut seps {
                        *count += csv_chars
                            .chars()
                            .take(50_000)
                            .filter(|&c| c == *sep)
                            .count();
                    }
                    seps.sort_by(|a, b| b.1.cmp(&a.1));
                    FileClassification::Spreadsheet(SpreadsheetFileType::Csv(seps[0].0))
                }
                Some("txt" | "log") => FileClassification::Document(DocumentFileType::Text),
                Some("pdf") => FileClassification::Document(DocumentFileType::Pdf),
                Some("rtf" | "odt" | "xps" | "wps" | "dotx" | "dotm" | "docx" | "docm" | "doc") => {
                    FileClassification::Document(DocumentFileType::Word)
                }
                Some("db" | "dump") => FileClassification::Database(DatabaseFileType::Db),
                Some("sqlite" | "sqlite3") => {
                    FileClassification::Database(DatabaseFileType::Sqlite)
                }
                Some("sql" | "mysql" | "pgsql") => {
                    FileClassification::Database(DatabaseFileType::Sql)
                }
                Some("pdb") => FileClassification::Database(DatabaseFileType::Pdb),
                Some("yaml") => FileClassification::Configuration(ConfigurationFileType::Yaml),
                Some("json") => FileClassification::Configuration(ConfigurationFileType::Json),
                Some("ini") => FileClassification::Configuration(ConfigurationFileType::Ini),
                Some("zip") => FileClassification::Archive(ArchiveFileType::Zip),
                Some("rar") => FileClassification::Archive(ArchiveFileType::Rar),
                _ => FileClassification::Regular,
            },
            None => FileClassification::Regular,
        }
    }

    fn classify_dir(&self) -> DirectoryClassification {
        let path = self.path();
        let file_name = path.file_name();
        match file_name.to_lowercase().as_deref() {
            Some(".git") => DirectoryClassification::VersionControl(VersionControlSystem::Git),
            Some(".svn") => DirectoryClassification::VersionControl(VersionControlSystem::Svn),
            _ => DirectoryClassification::Regular,
        }
    }

    fn classify(&self) -> EntryClassification {
        if self.file_type().is_dir() {
            EntryClassification::Dir(self.classify_dir())
        } else {
            EntryClassification::File(self.classify_file())
        }
    }
}

impl Display for DirectoryClassification {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DirectoryClassification::VersionControl(vcs) => match vcs {
                VersionControlSystem::Git => write!(f, "git"),
                VersionControlSystem::Svn => write!(f, "svn"),
            },
            DirectoryClassification::Regular => Ok(()),
        }
    }
}

impl Display for FileClassification {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret(ext) => match ext {
                SecretFileType::Env => write!(f, "dotenv"),
            },
            Self::Spreadsheet(ext) => match ext {
                SpreadsheetFileType::Excel => write!(f, "excel"),
                SpreadsheetFileType::Csv(separator) => write!(f, "csv('{}')", separator),
            },
            Self::Document(ext) => match ext {
                DocumentFileType::Pdf => write!(f, "pdf"),
                DocumentFileType::Text => write!(f, "txt"),
                DocumentFileType::Word => write!(f, "word"),
            },
            Self::Database(ext) => match ext {
                DatabaseFileType::Sqlite => write!(f, "sqlite"),
                DatabaseFileType::Sql => write!(f, "sql"),
                DatabaseFileType::Db => write!(f, "db"),
                DatabaseFileType::Pdb => write!(f, "pdb"),
            },
            Self::Configuration(ext) => match ext {
                ConfigurationFileType::Yaml => write!(f, "yaml"),
                ConfigurationFileType::Json => write!(f, "json"),
                ConfigurationFileType::Ini => write!(f, "ini"),
            },
            Self::Archive(ext) => match ext {
                ArchiveFileType::Zip => write!(f, "zip"),
                ArchiveFileType::Rar => write!(f, "rar"),
            },
            Self::Regular => Ok(()),
        }
    }
}

impl Display for EntryClassification {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(class) => write!(f, "{}", class),
            Self::Dir(class) => write!(f, "{}", class),
        }
    }
}

struct MetaData {
    name: String,
    date: DateTime<Utc>,
    tags: HashSet<String>,
    category: String,
}

fn scan_drive(root: &str) -> anyhow::Result<()> {
    let mut duplicates = 0usize;
    let re_numeric_prefix = Regex::new(r"^(\d+)_(.*?)$").unwrap();

    for entry in WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .filter_entry(|e| e.is_allowed())
        .filter_map(|e: std::result::Result<DirEntry, walkdir::Error>| e.ok())
    {
        let classification = entry.classify();
        match &classification {
            EntryClassification::File(
                FileClassification::Regular
                | FileClassification::Document(DocumentFileType::Text)
                | FileClassification::Spreadsheet(SpreadsheetFileType::Csv('\0')),
            ) => continue,
            EntryClassification::Dir(DirectoryClassification::Regular) => continue,
            _ => {}
        }

        if let EntryClassification::File(FileClassification::Document(DocumentFileType::Pdf)) =
            &classification
        {
            let path = entry.path().to_string_lossy().into_owned();
            let docspell_item = if let Some(parent) = entry.path().parent() {
                if parent.ancestors().any(|a| a.ends_with("by_tag")) {
                    assert_eq!(parent.file_name().unwrap().to_str().unwrap(), "files");

                    let mut metadata_pb = entry.path().to_path_buf();
                    metadata_pb.pop();
                    metadata_pb.pop();
                    metadata_pb.push("metadata.json");

                    if let Ok(meta_file) = File::open(&metadata_pb) {
                        let meta_reader = BufReader::new(meta_file);
                        let meta_data: Value = serde_json::from_reader(meta_reader)?;

                        let name = meta_data["name"].as_str().unwrap().to_owned();
                        let date = DateTime::<Utc>::from_timestamp_millis(
                            meta_data["date"].as_i64().expect("has no date"),
                        )
                        .unwrap();

                        let tags = HashSet::from_iter(
                            meta_data["tags"].as_array().unwrap().iter().map(|v| {
                                let meta = v.as_object().unwrap();
                                record::Tag {
                                    name: meta["name"].as_str().unwrap().to_owned(),
                                    category: meta["category"].as_str().unwrap().to_owned(),
                                }
                            }),
                        );

                        Some(record::Item {
                            path: path.clone(),
                            name,
                            date,
                            tags,
                            metadata_type: record::MetaDataType::Docspell,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let item = if let Some(item) = docspell_item {
                item
            } else {
                let file_stem = re_numeric_prefix
                    .replace(
                        &entry
                            .path()
                            .file_stem()
                            .unwrap_or(entry.path().file_name().unwrap())
                            .to_string_lossy(),
                        "$2",
                    )
                    .into_owned();

                let date_part = &file_stem[0..file_stem.len().min(10)];
                let date = NaiveDate::parse_from_str(date_part, "%F").map(|naive| {
                    naive
                        .and_hms_milli_opt(0, 0, 0, 0)
                        .unwrap()
                        .and_local_timezone(Utc)
                        .unwrap()
                });

                Item {
                    path,
                    name: file_stem,
                    date: date.unwrap_or_default(),
                    tags: HashSet::<Tag>::default(),
                    metadata_type: if date.is_ok() {
                        MetaDataType::Stem
                    } else {
                        MetaDataType::None
                    },
                }
            };

            let mut file = File::open(entry.path()).expect("failed to open pdf");
            let metadata = fs::metadata(entry.path()).expect("unable to read metadata");
            let mut buffer = vec![0; metadata.len() as usize];
            file.read_exact(&mut buffer).expect("buffer overflow");

            match unsafe { RECORDS.entry(blake3::hash(&buffer).to_string()) } {
                Vacant(vacant) => {
                    vacant.insert(item);
                }
                Occupied(mut occupant) => {
                    let record = occupant.get_mut();
                    duplicates += 1;

                    record.tags.extend(item.tags.clone());

                    if (item.metadata_type as usize) > (record.metadata_type as usize) {
                        record.name = item.name;
                        record.date = item.date;
                    }
                }
            }
        }
    }

    println!("removed {} duplicates", duplicates);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let _ = fs::remove_dir_all("C:\\tagged");
    let _ = fs::remove_dir_all("C:\\untagged");
    fs::create_dir("C:\\tagged")?;
    fs::create_dir("C:\\untagged")?;

    scan_drive(r#"C:\Users\root\Desktop\business\0"#)?;

    let mut tagged = 0usize;
    let mut untagged = 0usize;
    let mut with_date = 0usize;
    // tagged: 369, untagged: 928
    // tagged: 489, untagged: 1255
    // tagged: 489, untagged: 808

    unsafe {
        RECORDS.values().for_each(|item| {
            let has_tags = !item.tags.is_empty();
            if has_tags {
                tagged += 1
            } else {
                untagged += 1
            };

            if item.metadata_type != MetaDataType::None {
                with_date += 1;
            }

            let tags = if has_tags {
                Vec::from_iter(item.tags.iter().map(|t| t.name.as_str())).join(", ")
            } else {
                String::default()
            };

            let new_path = format!(
                r#"C:\{}\{} {}.pdf"#,
                if has_tags { "tagged" } else { "untagged" },
                item.date.format("%Y-%m-%d"),
                sanitize(&item.name)
            );

            // TODO: Add tags to folder structure (parse tag category meta_data["category"], prefer "business" over "private")
            println!("copy `{}` -> `{}` ({})", &item.path, &new_path, tags);
            fs::copy(&item.path, &new_path).expect("failed to copy");
        });
    }

    println!(
        "tagged: {}, untagged: {}, with_date: {}",
        tagged, untagged, with_date
    );
    Ok(())
}
