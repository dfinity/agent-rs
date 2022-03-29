pub enum Kind {
    Public,
    Private,
}

/// Add or overwrite a metadata section
pub fn add_metadata(m: &mut walrus::Module, visibility: Kind, name: &str, data: Vec<u8>) {
    let name = match visibility {
        Kind::Public => "icp:public ".to_owned(),
        Kind::Private => "icp:private ".to_owned(),
    } + name;
    drop(m.customs.remove_raw(&name));
    let custom_section = walrus::RawCustomSection { name, data };
    m.customs.add(custom_section);
}

/// List current metadata sections
pub fn list_metadata(m: &walrus::Module) -> Vec<&str> {
    m.customs
        .iter()
        .map(|section| section.1.name())
        .filter(|name| name.starts_with("icp:"))
        .collect()
}

/// Get the content of metadata
pub fn get_metadata<'a>(
    m: &'a walrus::Module,
    name: &'a str,
) -> Option<std::borrow::Cow<'a, [u8]>> {
    let public = "icp:public ".to_owned() + name;
    let private = "icp:private ".to_owned() + name;
    m.customs
        .iter()
        .find(|(_, section)| section.name() == public || section.name() == private)
        .map(|(_, section)| section.data(&walrus::IdsToIndices::default()))
}
