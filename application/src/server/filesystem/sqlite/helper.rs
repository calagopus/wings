use super::{
    QUERY_BUSY_TIMEOUT, QUERY_DEADLINE, QUERY_MEMORY_LIMIT, QueryResultSet,
    sandbox::{self, SandboxReport, SandboxUser},
};
use anyhow::{Context, bail, ensure};
use rusqlite::{OpenFlags, ffi};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    io::Read,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::process::ExitStatusExt,
    },
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::io::AsyncWriteExt;

pub const HELPER_ARG: &str = "__wings-sqlite";
const DIRECTORY_FD_ENV: &str = "WINGS_SQLITE_DIRECTORY_FD";
const JEMALLOC_CONF_ENV: (&str, &str) = ("_RJEM_MALLOC_CONF", "background_thread:false");

#[derive(Serialize, Deserialize)]
enum Task {
    Probe,
    Query {
        file_name: String,
        query: String,
        read_only: bool,
        max_rows: usize,
    },
}

#[derive(Serialize, Deserialize)]
struct Request {
    user: SandboxUser,
    task: Task,
}

#[derive(Serialize, Deserialize)]
struct Response {
    sandbox: SandboxReport,
    result: Result<Vec<QueryResultSet>, String>,
}

pub fn helper_main(args: &[OsString]) -> i32 {
    match run_helper(args) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{err:#}");
            1
        }
    }
}

fn run_helper(args: &[OsString]) -> Result<(), anyhow::Error> {
    ensure!(args.is_empty(), "the sqlite helper takes no arguments");
    let fd: RawFd = std::env::var(DIRECTORY_FD_ENV)
        .ok()
        .and_then(|fd| fd.parse().ok())
        .context("invalid database directory fd")?;
    ensure!(
        fd > 2,
        "the database directory fd collides with a standard stream"
    );
    // SAFETY: the parent passed this fd for the helper to own, and nothing else in this
    // process refers to it.
    let directory = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("failed to read the request")?;
    let request: Request = serde_json::from_str(&input).context("invalid request")?;

    rustix::process::fchdir(&directory).context("failed to enter the database directory")?;
    drop(directory);
    let sandbox = sandbox::apply(request.user).context("failed to sandbox the sqlite helper")?;

    let result = match request.task {
        Task::Probe => Ok(Vec::new()),
        Task::Query {
            file_name,
            query,
            read_only,
            max_rows,
        } => query_database(&file_name, &query, read_only, max_rows).map_err(|err| err.to_string()),
    };

    serde_json::to_writer(std::io::stdout().lock(), &Response { sandbox, result })
        .context("failed to write the response")?;

    Ok(())
}

fn query_database(
    file_name: &str,
    query: &str,
    read_only: bool,
    max_rows: usize,
) -> Result<Vec<QueryResultSet>, rusqlite::Error> {
    if file_name.is_empty() || file_name.contains('/') || file_name == ".." {
        return Err(rusqlite::Error::InvalidPath(file_name.into()));
    }

    let flags = if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;

    // a bare name starting with `file:` would be parsed as a URI, the prefix keeps it a path
    let connection = super::open(&Path::new(".").join(file_name), flags)?;
    // SAFETY: sqlite3_hard_heap_limit64 takes one i64 and only sets a process-wide limit.
    unsafe { ffi::sqlite3_hard_heap_limit64(QUERY_MEMORY_LIMIT as i64) };
    connection.busy_timeout(QUERY_BUSY_TIMEOUT)?;

    super::run_query(&connection, query, max_rows)
}

pub enum QueryOutcome {
    Results(Vec<QueryResultSet>),
    /// SQLite rejected or failed the query.
    Failed(String),
    TimedOut,
    /// The helper died from this signal, which a tenant can provoke by rewriting the
    /// database while the query runs.
    Crashed(i32),
}

pub struct QueryRequest<'a> {
    pub directory: BorrowedFd<'a>,
    pub file_name: &'a str,
    pub query: &'a str,
    pub read_only: bool,
    pub max_rows: usize,
    pub user: SandboxUser,
}

pub async fn run(request: QueryRequest<'_>) -> Result<QueryOutcome, anyhow::Error> {
    let task = Task::Query {
        file_name: request.file_name.to_owned(),
        query: request.query.to_owned(),
        read_only: request.read_only,
        max_rows: request.max_rows,
    };

    Ok(
        match spawn(
            helper_command(),
            request.directory,
            &Request {
                user: request.user,
                task,
            },
            QUERY_DEADLINE,
        )
        .await?
        {
            Exit::Finished(response) => {
                tracing::debug!(
                    applied = ?response.sandbox.applied,
                    skipped = ?response.sandbox.skipped,
                    "sqlite query helper sandbox"
                );

                match response.result {
                    Ok(results) => QueryOutcome::Results(results),
                    Err(message) => QueryOutcome::Failed(message),
                }
            }
            Exit::TimedOut => QueryOutcome::TimedOut,
            Exit::Crashed(signal) => QueryOutcome::Crashed(signal),
        },
    )
}

pub async fn probe(directory: &Path, user: SandboxUser) -> Result<SandboxReport, anyhow::Error> {
    let directory = std::fs::File::open(directory)
        .with_context(|| format!("failed to open {}", directory.display()))?;

    match spawn(
        helper_command(),
        directory.as_fd(),
        &Request {
            user,
            task: Task::Probe,
        },
        QUERY_DEADLINE,
    )
    .await?
    {
        Exit::Finished(response) => Ok(response.sandbox),
        Exit::TimedOut => bail!("the sqlite helper probe timed out"),
        Exit::Crashed(signal) => bail!("the sqlite helper probe died from signal {signal}"),
    }
}

enum Exit {
    Finished(Response),
    TimedOut,
    Crashed(i32),
}

fn inherit(fd: RawFd) -> rustix::io::Result<()> {
    // SAFETY: the parent keeps the directory open until the child has exec'd.
    rustix::io::fcntl_setfd(
        unsafe { BorrowedFd::borrow_raw(fd) },
        rustix::io::FdFlags::empty(),
    )
}

fn helper_command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new("/proc/self/exe");
    command.arg(HELPER_ARG).env_clear();

    command
}

async fn spawn(
    mut command: tokio::process::Command,
    directory: BorrowedFd<'_>,
    request: &Request,
    deadline: Duration,
) -> Result<Exit, anyhow::Error> {
    let raw = directory.as_raw_fd();
    command
        .env(DIRECTORY_FD_ENV, raw.to_string())
        .env(JEMALLOC_CONF_ENV.0, JEMALLOC_CONF_ENV.1)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // SAFETY: inherit issues a single fcntl on a borrowed fd and does not allocate or take
    // locks, so it is safe to run between fork and exec.
    unsafe {
        command.pre_exec(move || inherit(raw).map_err(Into::into));
    }

    let mut child = command
        .spawn()
        .context("failed to spawn the sqlite helper")?;
    let input = serde_json::to_vec(request)?;
    let mut stdin = child
        .stdin
        .take()
        .context("the sqlite helper has no stdin")?;
    if let Err(err) = stdin.write_all(&input).await {
        tracing::debug!("failed to send the request to the sqlite helper: {err}");
    }
    drop(stdin);

    let Ok(output) = tokio::time::timeout(deadline, child.wait_with_output()).await else {
        return Ok(Exit::TimedOut);
    };
    let output = output.context("failed to wait for the sqlite helper")?;

    if let Some(signal) = output.status.signal() {
        return Ok(Exit::Crashed(signal));
    }
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr).trim()
    );

    serde_json::from_slice(&output.stdout)
        .map(Exit::Finished)
        .context("invalid sqlite helper response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::filesystem::sqlite::{QueryResultSet, QueryValue, reexec_supported};
    use rustix::process::{geteuid, getgid, getuid};
    use std::{
        fs::File,
        io::Write,
        mem::ManuallyDrop,
        os::{
            fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
            unix::fs::{PermissionsExt, chown, symlink},
        },
        path::Path,
        process::Stdio,
        time::Instant,
    };
    use tokio::process::Command;

    const STDOUT_ENV: &str = "WINGS_SQLITE_TEST_STDOUT";
    const MODE_ENV: &str = "WINGS_SQLITE_TEST_MODE";
    const PID_ENV: &str = "WINGS_SQLITE_TEST_PID";
    const ENTRY: &str = "server::filesystem::sqlite::helper::tests::helper_entry";
    const STDOUT_FD: RawFd = 255;

    #[test]
    #[ignore = "entry point for the sqlite helper tests"]
    fn helper_entry() {
        let Some(stdout) = std::env::var(STDOUT_ENV)
            .ok()
            .and_then(|fd| fd.parse::<i32>().ok())
        else {
            return;
        };
        // SAFETY: the wrapper shell opened this descriptor as the parent's stdout pipe and
        // fd 1 stays open for the whole process.
        let (pipe, mut target) = unsafe {
            (
                OwnedFd::from_raw_fd(stdout),
                ManuallyDrop::new(OwnedFd::from_raw_fd(1)),
            )
        };
        rustix::io::dup2(&pipe, &mut target).unwrap();
        drop(pipe);

        if let Ok(path) = std::env::var(PID_ENV) {
            std::fs::write(path, rustix::process::getpid().as_raw_nonzero().to_string()).unwrap();
        }
        match std::env::var(MODE_ENV).as_deref() {
            Ok("crash") => {
                rustix::process::kill_process(
                    rustix::process::getpid(),
                    rustix::process::Signal::KILL,
                )
                .unwrap();
            }
            Ok("hang") => std::thread::sleep(Duration::from_secs(60)),
            _ => {}
        }

        let code = helper_main(&[]);
        std::io::stdout().flush().unwrap();
        std::process::exit(code);
    }

    const ENTRY_ARGS: [&str; 5] = [
        "--ignored",
        "--exact",
        ENTRY,
        "--test-threads=1",
        "--nocapture",
    ];

    fn park_stdout() -> std::io::Result<()> {
        // SAFETY: fd 1 is the stdout pipe std installed before running pre_exec hooks, and
        // the ManuallyDrop wrappers only serve as dup2 targets and are never closed.
        let (stdout, mut parked, mut target) = unsafe {
            (
                BorrowedFd::borrow_raw(1),
                ManuallyDrop::new(OwnedFd::from_raw_fd(STDOUT_FD)),
                ManuallyDrop::new(OwnedFd::from_raw_fd(1)),
            )
        };
        rustix::io::dup2(stdout, &mut parked)?;
        let null = rustix::fs::open(
            c"/dev/null",
            rustix::fs::OFlags::WRONLY,
            rustix::fs::Mode::empty(),
        )?;
        rustix::io::dup2(&null, &mut target)?;

        Ok(())
    }

    fn entry_command() -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(ENTRY_ARGS)
            .env(STDOUT_ENV, STDOUT_FD.to_string());
        // SAFETY: park_stdout only issues open/dup2/close syscalls and does not allocate.
        unsafe {
            command.pre_exec(park_stdout);
        }

        command
    }

    fn std_entry_command() -> std::process::Command {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(ENTRY_ARGS)
            .env(STDOUT_ENV, STDOUT_FD.to_string());
        // SAFETY: park_stdout only issues open/dup2/close syscalls and does not allocate.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut command, park_stdout);
        }

        command
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    struct Fixture {
        dir: tempfile::TempDir,
        directory: File,
        user: SandboxUser,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let user = match geteuid().is_root() {
                true => SandboxUser {
                    uid: 65534,
                    gid: 65534,
                },
                false => SandboxUser {
                    uid: getuid().as_raw(),
                    gid: getgid().as_raw(),
                },
            };
            let connection = rusqlite::Connection::open(dir.path().join("main.db")).unwrap();
            connection
                .execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (1), (2);")
                .unwrap();
            drop(connection);
            for path in [dir.path().to_path_buf(), dir.path().join("main.db")] {
                chown(&path, Some(user.uid), Some(user.gid)).unwrap();
            }
            let directory = File::open(dir.path()).unwrap();

            Self {
                dir,
                directory,
                user,
            }
        }

        fn path(&self) -> &Path {
            self.dir.path()
        }

        fn spawn_with(
            &self,
            user: SandboxUser,
            task: Task,
            mode: Option<&str>,
            deadline: Duration,
        ) -> Result<Exit, anyhow::Error> {
            let mut command = entry_command();
            if let Some(mode) = mode {
                command.env(MODE_ENV, mode);
                command.env(PID_ENV, self.path().join("pid"));
            }
            let request = Request { user, task };

            block_on(spawn(command, self.directory.as_fd(), &request, deadline))
        }

        fn finish(&self, task: Task) -> Response {
            match self.spawn_with(self.user, task, None, QUERY_DEADLINE) {
                Ok(Exit::Finished(response)) => response,
                Ok(Exit::TimedOut) => panic!("timed out"),
                Ok(Exit::Crashed(signal)) => panic!("crashed with {signal}"),
                Err(error) => panic!("{error:#}"),
            }
        }

        fn query(&self, file_name: &str, query: &str, read_only: bool) -> Response {
            self.finish(Task::Query {
                file_name: file_name.to_string(),
                query: query.to_string(),
                read_only,
                max_rows: 100,
            })
        }
    }

    fn texts(sets: &[QueryResultSet]) -> Vec<Vec<Option<String>>> {
        sets.last()
            .unwrap()
            .rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|value| match value {
                        QueryValue::Null => None,
                        QueryValue::Text { value, .. } | QueryValue::Binary { value, .. } => {
                            Some(value.clone())
                        }
                    })
                    .collect()
            })
            .collect()
    }

    fn failure(response: Response) -> String {
        match response.result {
            Err(message) => message,
            Ok(_) => panic!("query succeeded"),
        }
    }

    fn assert_layers(report: &SandboxReport) {
        let mut names: Vec<&str> = report
            .applied
            .iter()
            .map(String::as_str)
            .chain(report.skipped.iter().map(|(name, _)| name.as_str()))
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "capability bounding set",
                "chroot",
                "landlock",
                "privilege lock",
                "resource limits",
                "server user",
                "user namespace",
            ],
            "{report:?}"
        );
        if geteuid().is_root() {
            assert!(
                report.applied.iter().any(|name| name == "server user")
                    || report.applied.iter().any(|name| name == "user namespace"),
                "{report:?}"
            );
        }
    }

    // spawn

    #[test]
    fn probe_reports_the_sandbox_without_results() {
        if !reexec_supported() {
            return;
        }
        let fixture = Fixture::new();
        let response = fixture.finish(Task::Probe);

        assert_layers(&response.sandbox);
        assert!(matches!(response.result, Ok(ref sets) if sets.is_empty()));
    }

    #[test]
    fn runs_queries_in_the_directory_as_the_server_user() {
        if !reexec_supported() {
            return;
        }
        let fixture = Fixture::new();

        let response = fixture.query("main.db", "SELECT x FROM t ORDER BY x", true);
        assert_layers(&response.sandbox);
        let sets = response.result.unwrap();
        assert_eq!(
            texts(&sets),
            [[Some("1".to_string())], [Some("2".to_string())]]
        );

        failure(fixture.query("main.db", "INSERT INTO t VALUES (3)", true));
        fixture
            .query("main.db", "INSERT INTO t VALUES (4)", false)
            .result
            .unwrap();
        let connection = rusqlite::Connection::open(fixture.path().join("main.db")).unwrap();
        let rows: Vec<i64> = connection
            .prepare("SELECT x FROM t ORDER BY x")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows, [1, 2, 4]);

        if geteuid().is_root() {
            let secret = fixture.path().join("secret.db");
            std::fs::copy(fixture.path().join("main.db"), &secret).unwrap();
            chown(&secret, Some(0), Some(0)).unwrap();
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
            failure(fixture.query("secret.db", "SELECT x FROM t", true));
        }
    }

    #[test]
    fn rejects_names_that_leave_the_directory() {
        if !reexec_supported() {
            return;
        }
        let fixture = Fixture::new();
        std::fs::create_dir(fixture.path().join("sub")).unwrap();
        std::fs::copy(
            fixture.path().join("main.db"),
            fixture.path().join("sub/inner.db"),
        )
        .unwrap();

        for name in [
            "",
            "..",
            "../main.db",
            "sub/inner.db",
            "/etc/passwd",
            "./main.db",
        ] {
            let message = failure(fixture.query(name, "SELECT 1", true));
            assert!(message.starts_with("Invalid path"), "{name:?}: {message}");
        }

        symlink("main.db", fixture.path().join("link.db")).unwrap();
        failure(fixture.query("link.db", "SELECT x FROM t", true));
        failure(fixture.query("link.db", "INSERT INTO t VALUES (9)", false));
    }

    #[test]
    fn reports_sqlite_errors_as_results() {
        if !reexec_supported() {
            return;
        }
        let fixture = Fixture::new();

        let message = failure(fixture.query("main.db", "SELECT * FROM missing", true));
        assert!(message.contains("no such table: missing"), "{message}");

        failure(fixture.query("absent.db", "CREATE TABLE t(x)", false));
        assert!(!fixture.path().join("absent.db").exists());
    }

    #[test]
    fn refuses_to_query_as_root() {
        if !geteuid().is_root() || !reexec_supported() {
            return;
        }
        let fixture = Fixture::new();

        for user in [
            SandboxUser { uid: 0, gid: 65534 },
            SandboxUser { uid: 65534, gid: 0 },
            SandboxUser { uid: 0, gid: 0 },
        ] {
            let task = Task::Query {
                file_name: "main.db".to_string(),
                query: "INSERT INTO t VALUES (5)".to_string(),
                read_only: false,
                max_rows: 100,
            };
            match fixture.spawn_with(user, task, None, QUERY_DEADLINE) {
                Err(error) => {
                    let message = format!("{error:#}");
                    assert!(
                        message.contains("refusing to run queries as root"),
                        "{message}"
                    );
                }
                Ok(_) => panic!("{user:?}: helper did not fail"),
            }
        }

        let connection = rusqlite::Connection::open(fixture.path().join("main.db")).unwrap();
        let count: i64 = connection
            .query_row("SELECT count(*) FROM t WHERE x = 5", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn maps_crashes_and_deadlines() {
        if !reexec_supported() {
            return;
        }
        let fixture = Fixture::new();

        match fixture.spawn_with(fixture.user, Task::Probe, Some("crash"), QUERY_DEADLINE) {
            Ok(Exit::Crashed(signal)) => assert_eq!(signal, 9),
            Ok(_) => panic!("crash was not reported"),
            Err(error) => panic!("{error:#}"),
        }

        let started = Instant::now();
        match fixture.spawn_with(
            fixture.user,
            Task::Probe,
            Some("hang"),
            Duration::from_millis(500),
        ) {
            Ok(Exit::TimedOut) => {}
            Ok(_) => panic!("deadline was not reported"),
            Err(error) => panic!("{error:#}"),
        }
        assert!(started.elapsed() < Duration::from_secs(10));

        let pid = std::fs::read_to_string(fixture.path().join("pid")).unwrap();
        let gone = (0..50).any(|_| {
            let alive = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .is_ok_and(|stat| !stat.contains(") Z "));
            if alive {
                std::thread::sleep(Duration::from_millis(100));
            }
            !alive
        });
        assert!(gone, "helper {pid} outlived its deadline");
    }

    // helper_main

    #[test]
    fn fails_hard_on_a_bad_environment_or_request() {
        if !reexec_supported() {
            return;
        }
        let fixture = Fixture::new();
        let directory = rustix::fs::open(
            fixture.path(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let fd = directory.as_raw_fd();
        let request = serde_json::to_string(&Request {
            user: fixture.user,
            task: Task::Probe,
        })
        .unwrap();

        let cases = [
            (None, request.as_str()),
            (Some("abc".to_string()), request.as_str()),
            (Some("2".to_string()), request.as_str()),
            (Some("-1".to_string()), request.as_str()),
            (Some(fd.to_string()), "not json"),
            (Some(fd.to_string()), ""),
            (
                Some(fd.to_string()),
                "{\"user\":{\"uid\":1,\"gid\":1},\"task\":\"Other\"}",
            ),
        ];
        for (fd_env, stdin) in cases {
            let mut command = std_entry_command();
            command
                .env("_RJEM_MALLOC_CONF", "background_thread:false")
                .env_remove("WINGS_SQLITE_DIRECTORY_FD")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(fd_env) = &fd_env {
                command.env("WINGS_SQLITE_DIRECTORY_FD", fd_env);
            }
            let mut child = command.spawn().unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(stdin.as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();

            assert_eq!(output.status.code(), Some(1), "{fd_env:?} {stdin:?}");
            assert!(output.stdout.is_empty(), "{fd_env:?} {stdin:?}");
            assert!(!output.stderr.is_empty(), "{fd_env:?} {stdin:?}");
        }

        let mut child = std_entry_command()
            .env("_RJEM_MALLOC_CONF", "background_thread:false")
            .env("WINGS_SQLITE_DIRECTORY_FD", fd.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(request.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: Response = serde_json::from_slice(&output.stdout).unwrap();
        assert_layers(&response.sandbox);
    }
}
