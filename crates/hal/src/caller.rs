//! 调用方 UID → 包名映射。
//!
//! binder 调用自带 caller UID（`rsbinder::ThreadState::get_calling_uid()`），
//! 反查 `/data/system/packages.list` 得到该 uid 的所有包名，用于白名单匹配。
//!
//! packages.list 每行格式：
//! `<packageName> <uid> <debugFlag> <dataPath> <seinfo> ...`
//! 只取前两列做 uid 匹配。

use std::path::Path;

/// 默认 packages.list 路径。
pub const PACKAGES_LIST: &str = "/data/system/packages.list";

/// 返回指定 uid 对应的所有包名。
///
/// 文件不可读 / 解析失败时返回空 Vec（调用方据此保守处理——
/// 黑名单匹配失败时**不豁免**，继续伪造，因为黑名单只是可选安全网）。
pub fn packages_for_uid(uid: u32) -> Vec<String> {
    packages_for_uid_from(Path::new(PACKAGES_LIST), uid)
}

pub fn packages_for_uid_from(path: &Path, uid: u32) -> Vec<String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let pkg = it.next()?;
            let uid_str = it.next()?;
            let pkg_uid: u32 = uid_str.parse().ok()?;
            (pkg_uid == uid).then(|| pkg.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uid() {
        let tmp = std::env::temp_dir().join("fktee_hal_packages_list_test");
        std::fs::write(
            &tmp,
            "com.example.app 10042 0 /data/user/0/com.example.app default\n\
             com.other 10043 0 /data/user/0/com.other default\n",
        )
        .unwrap();
        let pkgs = packages_for_uid_from(&tmp, 10042);
        assert_eq!(pkgs, vec!["com.example.app".to_string()]);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn missing_file_returns_empty() {
        assert!(packages_for_uid_from(Path::new("/nonexistent"), 1).is_empty());
    }
}
