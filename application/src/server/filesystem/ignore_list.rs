use crate::server::filesystem::{
    cap::{CapFilesystem, FileType},
    uploads::ignore_match_path,
    virtualfs::{IgnoreVerdict, IsIgnoredFn},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone)]
pub struct IgnoreList {
    matcher: ignore::gitignore::Gitignore,
    descend: Arc<[DescendRule]>,
    descend_all: bool,
}

impl IgnoreList {
    pub fn builder() -> IgnoreListBuilder {
        let mut builder = ignore::gitignore::GitignoreBuilder::new("");
        builder.allow_unclosed_class(false);

        IgnoreListBuilder {
            builder,
            descend: Vec::new(),
            descend_all: false,
            raw: compact_str::CompactString::default(),
        }
    }

    pub fn from_lines<S: AsRef<str>>(
        lines: impl IntoIterator<Item = S>,
    ) -> Result<Self, ignore::Error> {
        let mut builder = Self::builder();
        for line in lines {
            builder.push_line(line.as_ref());
        }

        builder.build()
    }

    pub fn try_from_lines<S: AsRef<str>>(
        lines: impl IntoIterator<Item = S>,
    ) -> Result<Self, ignore::Error> {
        let mut builder = Self::builder();
        for line in lines {
            builder.try_push_line(line.as_ref())?;
        }

        builder.build()
    }

    pub fn empty() -> Self {
        Self {
            matcher: ignore::gitignore::Gitignore::empty(),
            descend: Arc::new([]),
            descend_all: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.matcher.is_empty()
    }

    pub fn has_reincludes(&self) -> bool {
        self.descend_all || !self.descend.is_empty()
    }

    fn should_descend(&self, path: &Path) -> bool {
        if self.descend_all {
            return true;
        }

        let path = path.to_string_lossy();
        let path = path.trim_start_matches("./").trim_start_matches('/');

        self.descend.iter().any(|rule| rule.covers(path))
    }

    fn excluded(&self, path: &Path, is_dir: bool) -> bool {
        if path.as_os_str().is_empty() || path == Path::new(".") {
            return false;
        }

        self.matcher
            .matched(ignore_match_path(path), is_dir)
            .is_ignore()
    }

    pub fn verdict(&self, file_type: FileType, path: PathBuf) -> IgnoreVerdict {
        if !self.excluded(&path, file_type.is_dir()) {
            IgnoreVerdict::Keep(path)
        } else if file_type.is_dir() && self.should_descend(&path) {
            IgnoreVerdict::Descend(path)
        } else {
            IgnoreVerdict::Skip
        }
    }

    pub fn verdict_as(
        &self,
        file_type: FileType,
        match_path: &Path,
        path: PathBuf,
    ) -> IgnoreVerdict {
        if !self.excluded(match_path, file_type.is_dir()) {
            IgnoreVerdict::Keep(path)
        } else if file_type.is_dir() && self.should_descend(match_path) {
            IgnoreVerdict::Descend(path)
        } else {
            IgnoreVerdict::Skip
        }
    }

    pub fn is_ignored(&self, path: &Path, file_type: FileType) -> bool {
        self.excluded(path, file_type.is_dir())
    }

    pub fn is_ignored_subtree(&self, path: &Path, file_type: FileType) -> bool {
        self.excluded(path, file_type.is_dir())
            && !(file_type.is_dir() && self.should_descend(path))
    }

    /// The entries an engine without re-includes has to exclude to keep exactly
    /// what this list keeps: every skipped entry at the edge of the walk, with an
    /// excluded directory that turned out to hold nothing kept collapsed into one
    /// entry.
    pub fn exclusion_frontier(
        &self,
        filesystem: &CapFilesystem,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        let mut frontier = Vec::new();
        self.frontier_below(filesystem, Path::new(""), &mut frontier)?;

        Ok(frontier)
    }

    fn frontier_below(
        &self,
        filesystem: &CapFilesystem,
        directory: &Path,
        frontier: &mut Vec<PathBuf>,
    ) -> Result<bool, std::io::Error> {
        let mut kept_any = false;
        let mut entries = filesystem.read_dir(directory)?;

        while let Some(entry) = entries.next_entry() {
            let (file_type, name) = entry?;

            match self.verdict(file_type, directory.join(&name)) {
                IgnoreVerdict::Keep(path) => {
                    kept_any = true;
                    if file_type.is_dir() {
                        self.frontier_below(filesystem, &path, frontier)?;
                    }
                }
                IgnoreVerdict::Skip => frontier.push(directory.join(&name)),
                IgnoreVerdict::Descend(path) => {
                    let mark = frontier.len();
                    if self.frontier_below(filesystem, &path, frontier)? {
                        kept_any = true;
                    } else {
                        frontier.truncate(mark);
                        frontier.push(path);
                    }
                }
            }
        }

        Ok(kept_any)
    }
}

impl From<IgnoreList> for IsIgnoredFn {
    fn from(list: IgnoreList) -> Self {
        Self::from(move |file_type: FileType, path: PathBuf| list.verdict(file_type, path))
    }
}

pub struct IgnoreListBuilder {
    builder: ignore::gitignore::GitignoreBuilder,
    descend: Vec<DescendRule>,
    descend_all: bool,
    raw: compact_str::CompactString,
}

impl IgnoreListBuilder {
    pub fn case_insensitive(&mut self, yes: bool) -> Result<&mut Self, ignore::Error> {
        self.builder.case_insensitive(yes)?;

        Ok(self)
    }

    pub fn push_line(&mut self, line: &str) {
        self.try_push_line(line).ok();
    }

    pub fn try_push_line(&mut self, line: &str) -> Result<(), ignore::Error> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(());
        }

        let (negated, body) = match trimmed.strip_prefix('!') {
            Some(body) => ("!", body),
            None => ("", trimmed),
        };
        if body.is_empty() {
            return Ok(());
        }

        self.builder.add_line(None, trimmed)?;

        let dir_only = body.ends_with('/');
        let stem = body.trim_end_matches('/');
        let mut needs_descend = !negated.is_empty();
        let companion = match stem.strip_suffix("/**") {
            Some("") => None,
            Some(_) if dir_only => {
                needs_descend = true;
                None
            }
            Some(parent) if parent.contains('/') => Some(format!("{negated}{parent}")),
            Some(parent) => Some(format!("{negated}/{parent}")),
            None if stem.is_empty() => None,
            None if stem.contains('/') => Some(format!("{negated}{stem}/**")),
            None => Some(format!("{negated}**/{stem}/**")),
        };
        if let Some(companion) = companion {
            self.builder.add_line(None, &companion).ok();
        }

        if needs_descend {
            match DescendRule::parse(body) {
                Some(rule) => self.descend.push(rule),
                None => self.descend_all = true,
            }
        }

        self.raw.push_str(trimmed);
        self.raw.push('\n');

        Ok(())
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn build(self) -> Result<IgnoreList, ignore::Error> {
        Ok(IgnoreList {
            matcher: self.builder.build()?,
            descend: self.descend.into(),
            descend_all: self.descend_all,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DescendRule {
    prefix: compact_str::CompactString,
    tail: Option<usize>,
}

impl DescendRule {
    fn parse(pattern: &str) -> Option<Self> {
        let pattern = pattern.trim_end_matches('/');
        if !pattern.contains('/') {
            return None;
        }

        let pattern = pattern.trim_start_matches('/');
        let mut segments = pattern.split('/').peekable();
        let mut prefix = compact_str::CompactString::default();

        while let Some(segment) = segments.next_if(|segment| !segment.contains(['*', '?', '['])) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
        }

        if prefix.is_empty() {
            return None;
        }

        let tail = segments.try_fold(0, |tail, segment| {
            (!segment.contains("**")).then_some(tail + 1)
        });

        Some(Self { prefix, tail })
    }

    fn covers(&self, path: &str) -> bool {
        if path == self.prefix {
            return true;
        }

        if let Some(rest) = self.prefix.strip_prefix(path) {
            return rest.starts_with('/');
        }

        match path.strip_prefix(self.prefix.as_str()) {
            Some(rest) if rest.starts_with('/') => self
                .tail
                .is_none_or(|tail| rest.matches('/').count() < tail),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUG_REPORT_IGNORE: &[&str] = &[
        "*",
        "!.pteroignore",
        "!game/csgo/gamemodes_server.txt",
        "!game/csgo/addons",
        "game/csgo/addons/counterstrikesharp/data/demos/*",
        "!game/csgo/cfg",
    ];

    const CSGO_TREE: &[&str] = &[
        ".pteroignore",
        "srcds_run",
        "game/csgo/gamemodes_server.txt",
        "game/csgo/other.txt",
        "game/csgo/cfg/server.cfg",
        "game/csgo/cfg/nested/deep.cfg",
        "game/csgo/addons/metamod/metamod.vdf",
        "game/csgo/addons/counterstrikesharp/plugins/plugin.dll",
        "game/csgo/addons/counterstrikesharp/data/demos/demo1.dem",
        "game/hl2/hl2.txt",
    ];

    fn tree_children(files: &[&str], dir: &str) -> Vec<(String, bool)> {
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let mut children: Vec<(String, bool)> = Vec::new();

        for file in files {
            let Some(rest) = file.strip_prefix(&prefix) else {
                continue;
            };

            let (name, is_dir) = match rest.split_once('/') {
                Some((name, _)) => (name, true),
                None => (rest, false),
            };
            let path = format!("{prefix}{name}");

            if !children.iter().any(|(existing, _)| existing == &path) {
                children.push((path, is_dir));
            }
        }

        children
    }

    fn walk(is_ignored: &IsIgnoredFn, files: &[&str]) -> Vec<String> {
        let mut kept = Vec::new();
        let mut stack = vec![String::new()];

        while let Some(dir) = stack.pop() {
            for (path, is_dir) in tree_children(files, &dir) {
                let verdict = is_ignored(FileType::from_is_dir(is_dir), PathBuf::from(&path));
                let kept_entry = verdict.is_kept();

                if verdict.descend().is_none() {
                    continue;
                }

                if is_dir {
                    stack.push(path.clone());
                }
                if kept_entry {
                    kept.push(path);
                }
            }
        }

        kept.sort();
        kept
    }

    fn plain_matcher(lines: &[&str]) -> Result<IsIgnoredFn, ignore::Error> {
        let mut builder = ignore::gitignore::GitignoreBuilder::new("");
        for line in lines {
            builder.add_line(None, line)?;
        }
        let matcher = builder.build()?;

        Ok(IsIgnoredFn::from(
            move |file_type: FileType, path: PathBuf| {
                if matcher.matched(&path, file_type.is_dir()).is_ignore() {
                    IgnoreVerdict::Skip
                } else {
                    IgnoreVerdict::Keep(path)
                }
            },
        ))
    }

    // IgnoreList
    #[test]
    fn subtree_reincludes_survive_a_blanket_exclude() -> Result<(), anyhow::Error> {
        let ignore = IgnoreList::from_lines(BUG_REPORT_IGNORE)?;

        assert_eq!(
            walk(&plain_matcher(BUG_REPORT_IGNORE)?, CSGO_TREE),
            [".pteroignore"]
        );
        assert_eq!(
            walk(&IsIgnoredFn::from(ignore), CSGO_TREE),
            [
                ".pteroignore",
                "game/csgo/addons",
                "game/csgo/addons/counterstrikesharp",
                "game/csgo/addons/counterstrikesharp/data",
                "game/csgo/addons/counterstrikesharp/data/demos",
                "game/csgo/addons/counterstrikesharp/plugins",
                "game/csgo/addons/counterstrikesharp/plugins/plugin.dll",
                "game/csgo/addons/metamod",
                "game/csgo/addons/metamod/metamod.vdf",
                "game/csgo/cfg",
                "game/csgo/cfg/nested",
                "game/csgo/cfg/nested/deep.cfg",
                "game/csgo/cfg/server.cfg",
                "game/csgo/gamemodes_server.txt",
            ]
        );

        Ok(())
    }

    #[test]
    fn lists_without_reincludes_prune_exactly_like_gitignore() -> Result<(), anyhow::Error> {
        const LINES: &[&str] = &["logs/", "*.tmp", "cache", "game/csgo/addons/data"];
        const TREE: &[&str] = &[
            "keep.txt",
            "a.tmp",
            "x.tmp/inner.txt",
            "logs/latest.log",
            "logs/old/2024.log",
            "cache/x/y.bin",
            "game/csgo/cfg/server.cfg",
            "game/csgo/addons/data/db.sqlite",
        ];

        let ignore = IgnoreList::from_lines(LINES)?;
        assert!(ignore.descend.is_empty());
        assert!(!ignore.descend_all);

        let kept = walk(&IsIgnoredFn::from(ignore), TREE);
        assert_eq!(
            kept,
            [
                "game",
                "game/csgo",
                "game/csgo/addons",
                "game/csgo/cfg",
                "game/csgo/cfg/server.cfg",
                "keep.txt",
            ]
        );
        assert_eq!(kept, walk(&plain_matcher(LINES)?, TREE));

        Ok(())
    }

    #[test]
    fn per_level_negations_keep_their_gitignore_meaning() -> Result<(), anyhow::Error> {
        const LINES: &[&str] = &[
            "/*",
            "!/game/",
            "/game/*",
            "!/game/csgo/",
            "/game/csgo/*",
            "!/game/csgo/cfg/",
        ];
        const TREE: &[&str] = &[
            "top.txt",
            "game/hl2/x.txt",
            "game/csgo/other.txt",
            "game/csgo/maps/de_dust.bsp",
            "game/csgo/cfg/server.cfg",
            "game/csgo/cfg/nested/deep.cfg",
        ];

        let expected = walk(&plain_matcher(LINES)?, TREE);
        assert_eq!(
            expected,
            [
                "game",
                "game/csgo",
                "game/csgo/cfg",
                "game/csgo/cfg/nested",
                "game/csgo/cfg/nested/deep.cfg",
                "game/csgo/cfg/server.cfg",
            ]
        );
        assert_eq!(
            walk(&IsIgnoredFn::from(IgnoreList::from_lines(LINES)?), TREE),
            expected
        );

        Ok(())
    }

    #[test]
    fn egg_denylist_outranks_user_reincludes() -> Result<(), anyhow::Error> {
        const LINES: &[&str] = &["*", "!config", "!secrets", "config/secret.key", "secrets"];
        const TREE: &[&str] = &[
            "other.txt",
            "config/server.yml",
            "config/secret.key",
            "secrets/deep/token.txt",
        ];

        assert_eq!(
            walk(&IsIgnoredFn::from(IgnoreList::from_lines(LINES)?), TREE),
            ["config", "config/server.yml"]
        );

        Ok(())
    }

    #[test]
    fn only_branches_holding_a_reinclude_are_descended() -> Result<(), anyhow::Error> {
        let ignore = IsIgnoredFn::from(IgnoreList::from_lines(["*", "!game/csgo/cfg"])?);

        assert_eq!(
            ignore(FileType::Dir, "game".into()),
            IgnoreVerdict::Descend("game".into())
        );
        assert_eq!(
            ignore(FileType::Dir, "game/csgo/cfg".into()),
            IgnoreVerdict::Keep("game/csgo/cfg".into())
        );
        assert_eq!(ignore(FileType::Dir, "other".into()), IgnoreVerdict::Skip);
        assert_eq!(ignore(FileType::File, "game".into()), IgnoreVerdict::Skip);

        let ignore = IsIgnoredFn::from(IgnoreList::from_lines(["*", "!*.txt"])?);

        assert_eq!(
            ignore(FileType::Dir, "other".into()),
            IgnoreVerdict::Descend("other".into())
        );
        assert_eq!(
            ignore(FileType::File, "a/b/c.txt".into()),
            IgnoreVerdict::Keep("a/b/c.txt".into())
        );

        let ignore = IsIgnoredFn::from(IgnoreList::from_lines(["*", "!/game", "/game/cache"])?);

        assert_eq!(
            ignore(FileType::Dir, "game".into()),
            IgnoreVerdict::Keep("game".into())
        );
        assert_eq!(
            ignore(FileType::Dir, "game/cache".into()),
            IgnoreVerdict::Skip
        );
        assert_eq!(
            ignore(FileType::Dir, "/game/cache".into()),
            IgnoreVerdict::Skip
        );
        assert_eq!(ignore(FileType::Dir, "other".into()), IgnoreVerdict::Skip);

        let ignore = IsIgnoredFn::from(IgnoreList::from_lines(["*", "!game", "game/cache"])?);

        assert_eq!(
            ignore(FileType::Dir, "game/cache".into()),
            IgnoreVerdict::Descend("game/cache".into())
        );
        assert_eq!(
            ignore(FileType::Dir, "other".into()),
            IgnoreVerdict::Descend("other".into())
        );
        assert_eq!(
            ignore(FileType::File, "other/game".into()),
            IgnoreVerdict::Keep("other/game".into())
        );

        let ignore = IsIgnoredFn::from(IgnoreList::from_lines(["*", "!game/*/cfg"])?);

        assert_eq!(
            ignore(FileType::Dir, "game".into()),
            IgnoreVerdict::Descend("game".into())
        );
        assert_eq!(
            ignore(FileType::Dir, "game/csgo".into()),
            IgnoreVerdict::Descend("game/csgo".into())
        );
        assert_eq!(
            ignore(FileType::Dir, "game/csgo/cfg".into()),
            IgnoreVerdict::Keep("game/csgo/cfg".into())
        );
        assert_eq!(
            ignore(FileType::Dir, "game/csgo/other".into()),
            IgnoreVerdict::Skip
        );

        Ok(())
    }

    #[test]
    fn wildcard_tail_reincludes_match_at_their_own_depth_only() -> Result<(), anyhow::Error> {
        const LINES: &[&str] = &["*", "!game/*/cfg"];
        const TREE: &[&str] = &[
            "top.txt",
            "game/x.txt",
            "game/csgo/other/c.txt",
            "game/csgo/cfg/a.cfg",
            "game/csgo/cfg/deep/b.cfg",
            "game/hl2/cfg/d.cfg",
            "game/hl2/maps/cfg/e.cfg",
            "game/a/b/cfg/x.cfg",
        ];

        assert_eq!(
            walk(&IsIgnoredFn::from(IgnoreList::from_lines(LINES)?), TREE),
            [
                "game/csgo/cfg",
                "game/csgo/cfg/a.cfg",
                "game/csgo/cfg/deep",
                "game/csgo/cfg/deep/b.cfg",
                "game/hl2/cfg",
                "game/hl2/cfg/d.cfg",
            ]
        );

        Ok(())
    }

    #[test]
    fn slash_free_reincludes_are_found_under_any_excluded_directory() -> Result<(), anyhow::Error> {
        const LINES: &[&str] = &["*", "!.pteroignore"];
        const TREE: &[&str] = &[".pteroignore", "srcds_run", "game/csgo/.pteroignore"];

        assert_eq!(
            walk(&IsIgnoredFn::from(IgnoreList::from_lines(LINES)?), TREE),
            [".pteroignore", "game/csgo/.pteroignore"]
        );

        Ok(())
    }

    #[test]
    fn a_subtree_glob_also_matches_its_own_root() -> Result<(), anyhow::Error> {
        const LINES: &[&str] = &["/*/**", "!/logs/**"];
        const TREE: &[&str] = &["top.txt", "game/x.txt", "logs/latest.log"];

        assert_eq!(
            walk(&IsIgnoredFn::from(IgnoreList::from_lines(LINES)?), TREE),
            ["logs", "logs/latest.log"]
        );

        Ok(())
    }

    #[test]
    fn directory_only_subtree_excludes_leave_their_files_reachable() -> Result<(), anyhow::Error> {
        const LINES: &[&str] = &["*", "!game/csgo", "game/csgo/**/"];
        const TREE: &[&str] = &[
            "game/csgo/server.cfg",
            "game/csgo/cfg/server.cfg",
            "game/csgo/cfg/nested/deep.cfg",
            "other.txt",
        ];

        assert_eq!(
            walk(&IsIgnoredFn::from(IgnoreList::from_lines(LINES)?), TREE),
            [
                "game/csgo",
                "game/csgo/cfg/nested/deep.cfg",
                "game/csgo/cfg/server.cfg",
                "game/csgo/server.cfg",
            ]
        );

        const LONE: &[&str] = &["logs/**/"];
        const LONE_TREE: &[&str] = &["logs/a.log", "logs/old/b.log", "keep.txt"];

        assert_eq!(
            walk(&IsIgnoredFn::from(IgnoreList::from_lines(LONE)?), LONE_TREE),
            ["keep.txt", "logs", "logs/a.log", "logs/old/b.log"]
        );

        Ok(())
    }

    #[test]
    fn a_later_reinclude_below_a_later_exclude_is_reached_through_its_ancestors()
    -> Result<(), anyhow::Error> {
        const LINES: &[&str] = &[
            "*",
            "!game/csgo/addons",
            "game/csgo/addons/data",
            "!game/csgo/addons/data/keep",
        ];
        const TREE: &[&str] = &[
            "game/csgo/addons/plugin.dll",
            "game/csgo/addons/data/db.sqlite",
            "game/csgo/addons/data/keep/note.txt",
        ];

        assert_eq!(
            walk(&IsIgnoredFn::from(IgnoreList::from_lines(LINES)?), TREE),
            [
                "game/csgo/addons",
                "game/csgo/addons/data/keep",
                "game/csgo/addons/data/keep/note.txt",
                "game/csgo/addons/plugin.dll",
            ]
        );

        Ok(())
    }

    #[test]
    fn a_reinclude_after_an_exclude_wins_for_the_whole_subtree() -> Result<(), anyhow::Error> {
        const LINES: &[&str] = &["*", "game/cache", "!game"];
        const TREE: &[&str] = &["top.txt", "game/ok.txt", "game/cache/x.bin"];

        assert_eq!(
            walk(&IsIgnoredFn::from(IgnoreList::from_lines(LINES)?), TREE),
            ["game", "game/cache", "game/cache/x.bin", "game/ok.txt"]
        );

        Ok(())
    }

    #[test]
    fn slash_free_excludes_still_bite_below_a_reinclude() -> Result<(), anyhow::Error> {
        const LINES: &[&str] = &["*", "!game", "cache", "*.tmp", "logs/"];
        const TREE: &[&str] = &[
            "game/ok.txt",
            "game/cache/x.bin",
            "game/a/cache/y.bin",
            "game/a/x.tmp/inner.txt",
            "game/a/logs/z.log",
            "game/a/keep.bin",
            "cache/top.bin",
        ];

        assert_eq!(
            walk(&IsIgnoredFn::from(IgnoreList::from_lines(LINES)?), TREE),
            ["game", "game/a", "game/a/keep.bin", "game/ok.txt"]
        );

        const ANCHORED_LINES: &[&str] = &["*", "!game", "/cache"];
        const ANCHORED_TREE: &[&str] = &["game/cache/x.bin", "cache/y.bin", "game/ok.txt"];

        assert_eq!(
            walk(
                &IsIgnoredFn::from(IgnoreList::from_lines(ANCHORED_LINES)?),
                ANCHORED_TREE
            ),
            ["game", "game/cache", "game/cache/x.bin", "game/ok.txt"]
        );

        Ok(())
    }

    // IgnoreListBuilder
    #[test]
    fn comments_and_blank_lines_drop_out_without_ending_the_file() -> Result<(), anyhow::Error> {
        let mut builder = IgnoreList::builder();
        for line in [
            "# a comment",
            "",
            "   ",
            "  logs/  ",
            "!",
            "#another",
            "cache.db",
        ] {
            builder.push_line(line);
        }

        assert_eq!(builder.raw(), "logs/\ncache.db\n");
        let ignore = builder.build()?;

        let ignore = IsIgnoredFn::from(ignore);
        assert_eq!(ignore(FileType::Dir, "logs".into()), IgnoreVerdict::Skip);
        assert_eq!(
            ignore(FileType::File, "cache.db".into()),
            IgnoreVerdict::Skip
        );
        assert_eq!(
            ignore(FileType::File, "other.txt".into()),
            IgnoreVerdict::Keep("other.txt".into())
        );

        Ok(())
    }

    #[test]
    fn an_unparsable_line_is_dropped_or_refused_depending_on_the_entry_point()
    -> Result<(), anyhow::Error> {
        let lenient = IgnoreList::from_lines(["[abc", "*.log"])?;
        assert!(lenient.is_ignored(Path::new("server.log"), FileType::File));
        assert!(!lenient.is_ignored(Path::new("[abc"), FileType::File));

        assert!(IgnoreList::try_from_lines(["[abc", "*.log"]).is_err());
        assert!(IgnoreList::try_from_lines(["*.log", "!keep.log", "logs/"]).is_ok());

        Ok(())
    }

    #[test]
    fn the_root_is_never_an_entry_of_its_own_list() -> Result<(), anyhow::Error> {
        let ignore = IgnoreList::from_lines(["*"])?;

        for root in ["", "."] {
            assert!(!ignore.is_ignored(Path::new(root), FileType::Dir));
            assert!(!ignore.is_ignored_subtree(Path::new(root), FileType::Dir));
            assert_eq!(
                ignore.verdict(FileType::Dir, root.into()),
                IgnoreVerdict::Keep(root.into())
            );
        }
        assert!(ignore.is_ignored(Path::new("x"), FileType::File));

        Ok(())
    }

    #[test]
    fn point_checks_deny_the_whole_subtree_of_a_denied_name() -> Result<(), anyhow::Error> {
        let ignore = IgnoreList::from_lines(["secrets", "/config.yml"])?;

        assert!(ignore.is_ignored(Path::new("secrets"), FileType::Dir));
        assert!(ignore.is_ignored(Path::new("secrets/deep/token.txt"), FileType::File));
        assert!(ignore.is_ignored(Path::new("game/secrets/token.txt"), FileType::File));
        assert!(ignore.is_ignored(Path::new("config.yml"), FileType::File));
        assert!(!ignore.is_ignored(Path::new("game/config.yml"), FileType::File));
        assert!(!ignore.is_ignored(Path::new("secrets.txt"), FileType::File));

        Ok(())
    }

    #[test]
    fn a_descended_directory_is_denied_itself_but_not_as_a_subtree() -> Result<(), anyhow::Error> {
        let ignore = IgnoreList::from_lines(["*", "!game/csgo/cfg"])?;

        assert!(ignore.is_ignored(Path::new("game"), FileType::Dir));
        assert!(!ignore.is_ignored_subtree(Path::new("game"), FileType::Dir));
        assert!(ignore.is_ignored_subtree(Path::new("other"), FileType::Dir));
        assert!(ignore.is_ignored_subtree(Path::new("game/x.txt"), FileType::File));
        assert!(!ignore.is_ignored(Path::new("game/csgo/cfg"), FileType::Dir));
        assert!(ignore.has_reincludes());
        assert!(!IgnoreList::from_lines(["logs/", "*.tmp"])?.has_reincludes());
        assert!(!IgnoreList::empty().has_reincludes());
        assert!(IgnoreList::empty().is_empty());

        Ok(())
    }

    #[test]
    fn a_symlink_is_judged_by_its_target_but_keeps_its_own_path() -> Result<(), anyhow::Error> {
        let ignore = IgnoreList::from_lines(["secrets"])?;

        assert_eq!(
            ignore.verdict_as(FileType::Symlink, Path::new("secrets/key"), "link".into()),
            IgnoreVerdict::Skip
        );
        assert_eq!(
            ignore.verdict_as(FileType::Symlink, Path::new("public/key"), "link".into()),
            IgnoreVerdict::Keep("link".into())
        );

        Ok(())
    }

    // IgnoreList::exclusion_frontier
    #[test]
    fn the_exclusion_frontier_reproduces_the_kept_set_with_the_fewest_entries()
    -> Result<(), anyhow::Error> {
        let temp = tempfile::tempdir()?;
        let root = temp.path();

        for dir in [
            "game/csgo/cfg/nested",
            "game/csgo/addons/metamod",
            "game/cache/a/b",
            "game/hl2",
            "logs/old",
        ] {
            std::fs::create_dir_all(root.join(dir))?;
        }
        for file in [
            "top.txt",
            ".pteroignore",
            "game/x.txt",
            "game/csgo/other.txt",
            "game/csgo/cfg/server.cfg",
            "game/csgo/cfg/nested/deep.cfg",
            "game/csgo/addons/metamod/metamod.vdf",
            "game/cache/a/b/x.bin",
            "game/hl2/hl2.txt",
            "logs/old/a.log",
        ] {
            std::fs::write(root.join(file), file)?;
        }

        let frontier = |lines: &[&str]| -> Result<Vec<String>, anyhow::Error> {
            let ignore = IgnoreList::from_lines(lines)?;
            let filesystem = tokio_test::block_on(CapFilesystem::new(root))?;
            let mut frontier: Vec<String> = ignore
                .exclusion_frontier(&filesystem)?
                .into_iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect();
            frontier.sort();

            Ok(frontier)
        };

        assert_eq!(
            frontier(&["*", "!/game/csgo/cfg"])?,
            [
                ".pteroignore",
                "game/cache",
                "game/csgo/addons",
                "game/csgo/other.txt",
                "game/hl2",
                "game/x.txt",
                "logs",
                "top.txt",
            ]
        );
        assert_eq!(
            frontier(&["*", "!.pteroignore", "!*.cfg"])?,
            [
                "game/cache",
                "game/csgo/addons",
                "game/csgo/other.txt",
                "game/hl2",
                "game/x.txt",
                "logs",
                "top.txt",
            ]
        );
        assert_eq!(
            frontier(&["logs/", "*.bin", "game/csgo/addons"])?,
            ["game/cache/a/b/x.bin", "game/csgo/addons", "logs"]
        );
        assert!(frontier(&[])?.is_empty());

        Ok(())
    }

    // DescendRule
    #[test]
    fn descend_rule_bounds_the_wildcard_tail() {
        let rule = |prefix: &str, tail| DescendRule {
            prefix: prefix.into(),
            tail,
        };

        for (pattern, expected) in [
            ("game/csgo/addons", Some(rule("game/csgo/addons", Some(0)))),
            ("/game/csgo/", Some(rule("game/csgo", Some(0)))),
            ("/game", Some(rule("game", Some(0)))),
            ("game/*/data", Some(rule("game", Some(2)))),
            ("game/data?", Some(rule("game", Some(1)))),
            ("game/**/cfg", Some(rule("game", None))),
            ("game/*/**", Some(rule("game", None))),
            (".pteroignore", None),
            ("game", None),
            ("logs/", None),
            ("*", None),
            ("*.txt", None),
            ("**/logs", None),
            ("[abc]/x", None),
        ] {
            assert_eq!(DescendRule::parse(pattern), expected, "{pattern}");
        }
    }

    #[test]
    fn descend_rule_covers_ancestors_and_the_bounded_tail_only() {
        let literal = DescendRule::parse("game/csgo/addons").unwrap();
        assert!(literal.covers("game"));
        assert!(literal.covers("game/csgo"));
        assert!(literal.covers("game/csgo/addons"));
        assert!(!literal.covers("game/csgo/addons/x"));
        assert!(!literal.covers("game/csgo/other"));
        assert!(!literal.covers("gam"));
        assert!(!literal.covers("game/csgo/addonsx"));

        let bounded = DescendRule::parse("game/*/cfg").unwrap();
        assert!(bounded.covers("game"));
        assert!(bounded.covers("game/csgo"));
        assert!(!bounded.covers("game/csgo/other"));
        assert!(!bounded.covers("game/csgo/cfg/nested"));

        let unbounded = DescendRule::parse("game/**/cfg").unwrap();
        assert!(unbounded.covers("game/a/b/c/d"));
    }
}
