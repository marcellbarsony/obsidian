

```rs
fn main() {
    let path = Path::new("/home/marci/");
    match discover_dirs(path) {
        Ok(files) => {
            println!("Files :: {:?}", files);
        },
        Err(err) => eprintln!("[-] :: Error :: {}", err),
    };
}

fn discover_dirs(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let entries = fs::read_dir(path)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            let mut sub_files = discover_dirs(&path)?;
            files.append(&mut sub_files);
        } else {
            files.push(path);
        }
    }

    Ok(files)
}
```
