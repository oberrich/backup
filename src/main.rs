use chrono::{DateTime, Utc};
use core::ptr::addr_of_mut;
use core::{
    fmt,
    fmt::{Display, Formatter},
};
use once_cell::sync::Lazy;
use serde_json::{Result, Value};
use std::collections::btree_map::Entry::{Occupied, Vacant};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::os::windows::ffi::OsStringExt;
use walkdir::{DirEntry, WalkDir};

use regex::Regex;

use std::collections::HashSet;

mod record {
    use std::collections::HashSet;

    pub struct Item {
        pub path: String,
        pub name: String,
        pub tags: HashSet<String>,
        pub name_from_meta: bool,
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

fn scan_drive(root: &str, has_tag: bool) -> anyhow::Result<()> {
    //let mut og_tags = HashSet::<String>::new();
    let mut duplicates = 0usize;

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
            let owned_tag = if has_tag {
                let re = Regex::new(r"by_tag\\(\w*)\W").unwrap();
                let Some((_, [tag])) = re
                    .captures(entry.path().to_str().unwrap())
                    .map(|caps| caps.extract())
                else {
                    println!("no match!");
                    return Ok(());
                };
                Some(tag.to_owned())
            } else {
                None
            };

            let file_path = entry.path().to_string_lossy().into_owned();
            let mut file = File::open(&file_path).expect("failed to open pdf");
            let metadata = fs::metadata(entry.path()).expect("unable to read metadata");
            let mut buffer = vec![0; metadata.len() as usize];
            file.read_exact(&mut buffer).expect("buffer overflow");

            let file_name = entry.file_name().to_string_lossy().into_owned();
            let file_hash = blake3::hash(&buffer);

            let mut metadata_pb = entry.path().to_path_buf();
            metadata_pb.pop();
            metadata_pb.pop();
            metadata_pb.push("metadata.json");

            let (meta_name, meta_date) = if let Ok(meta_file) = File::open(&metadata_pb) {
                let meta_reader = BufReader::new(meta_file);
                let meta_data: Value = serde_json::from_reader(meta_reader)?;

                (
                    Some(meta_data["name"].as_str().unwrap().to_owned()),
                    chrono::DateTime::<Utc>::from_timestamp_millis(
                        meta_data["date"].as_i64().expect("has no date"),
                    ),
                )
            } else {
                (None, None)
            };

            let has_metadata = meta_name.is_some();
            assert_eq!(has_metadata, meta_date.is_some());

            if has_metadata {
                println!(
                    "meta name: {}, date: {}",
                    meta_name.as_ref().unwrap_or(&"none".to_owned()),
                    meta_date.expect("non-zero date").to_rfc3339()
                );
            }

            match unsafe { RECORDS.entry(file_hash.to_string()) } {
                Vacant(vacant) => {
                    vacant.insert(record::Item {
                        path: file_path,
                        name: meta_name.unwrap_or(file_name),
                        tags: owned_tag.map(|t| HashSet::from([t])).unwrap_or_default(),
                        name_from_meta: has_metadata,
                    });
                }
                Occupied(mut occupant) => {
                    let record = occupant.get_mut();
                    //println!("duplicate: {} ({})", record.name, file_hash);
                    duplicates += 1;

                    if has_metadata && !record.name_from_meta {
                        println!("from metadata: {} ({})", record.name, file_hash);
                        record.name = meta_name.unwrap_or(file_name);
                        record.name_from_meta = true;
                    }
                }
            }
        }

        // TODO: Flatten directory structure to primary_tag/2024-07-18 Document_Title_Thing (sanitize?)
    }

    println!("filtered {} duplicates", duplicates);

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let _ = fs::remove_dir_all("C:\\untagged");
    fs::create_dir("C:\\untagged")?;

    scan_drive(
        r#"C:\Users\root\Desktop\business\docspell-export-backup-scans-folder\docspell-export\business\by_tag"#,
        true,
    )?;
    scan_drive(r#"C:\Users\root\Desktop\business\0"#, false)?;

    let mut tagged = 0usize;
    let mut untagged = 0usize;
    // tagged: 369, untagged: 928

    unsafe {
        for (hash, item) in &mut *addr_of_mut!(RECORDS) {
            if !item.tags.is_empty() {
                tagged += 1;
                println!("{}: `C:\\tagged\\{}`", hash, item.name);
                //continue;
            } else {
                untagged += 1;
                //println!("{}: `C:\\untagged\\{}`", hash, item.name);
                fs::copy(&item.path, format!("C:\\untagged\\{}", item.name))?;
            }
        }
    }

    println!("tagged: {}, untagged: {}", tagged, untagged);

    Ok(())
}
