use core::{
    fmt,
    fmt::{Display, Formatter},
};
use once_cell::sync::Lazy;
use std::{ffi::OsStr, fs};
use std::{
    ffi::OsString,
    os::{
        raw::{c_char, c_int, c_ulong},
        windows::ffi::OsStringExt,
    },
    ptr::null_mut,
};
use walkdir::{DirEntry, WalkDir};
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
    TeamSpeak3, // TODO
    VSCode, // TODO: (vscode) Should this be split as its program specific and not generic? probably yeah figure it out tomorrow, gn! <3
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
    fn GetUserNameW(buf: *mut c_char, len: *mut c_ulong) -> c_int;
}

static PLATFORM: Lazy<Platform> = Lazy::new(|| unsafe {
    let mut name_buf: Vec<u16> = Vec::with_capacity(64);
    if GetUserNameW(name_buf.as_mut_ptr().cast(), null_mut()) == 0 {
        panic!("failed to get user name");
    }

    let name_os = OsString::from_wide(&name_buf);
    let name = name_os.as_os_str().to_string_lossy().into_owned();

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
        let platform = &*PLATFORM;

        self.path()
            .file_name()
            .and_then(OsStr::to_str)
            .map(|path| path == platform.sys_dir || path == platform.tmp_dir)
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
                // TODO: Add further excel formats
                Some("xlsl") => FileClassification::Spreadsheet(SpreadsheetFileType::Excel),
                Some("csv") => {
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
                Some("txt") | Some("log") => FileClassification::Document(DocumentFileType::Text),
                Some("pdf") => FileClassification::Document(DocumentFileType::Pdf),
                Some("rtf" | "odt" | "xps" | "wps" | "dotx" | "dotm" | "docx" | "docm" | "doc") => {
                    FileClassification::Document(DocumentFileType::Word)
                }
                Some("db") | Some("dump") => FileClassification::Database(DatabaseFileType::Db),
                Some("sqlite") | Some("sqlite3") => {
                    FileClassification::Database(DatabaseFileType::Sqlite)
                }
                Some("sql") | Some("mysql") | Some("pgsql") => {
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

fn scan_drive(letter: char) -> anyhow::Result<()> {
    for entry in WalkDir::new(format!("{}:{}", letter, PLATFORM_DIR_SEP))
        .follow_links(true)
        .into_iter()
        .filter_entry(|e| e.is_allowed())
        .filter_map(|e: std::result::Result<DirEntry, walkdir::Error>| e.ok())
    {
        let classification = entry.classify();
        match &classification {
            EntryClassification::File(class) => match class {
                FileClassification::Regular
                | FileClassification::Document(DocumentFileType::Text)
                | FileClassification::Spreadsheet(SpreadsheetFileType::Csv('\0')) => continue,
                _ => {}
            },
            EntryClassification::Dir(DirectoryClassification::Regular) => continue,
            _ => {}
        }

        println!("{} # {}", entry.path().display(), classification);
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    for letter in 'A'..='Z' {
        scan_drive(letter)?;
    }

    Ok(())
}
