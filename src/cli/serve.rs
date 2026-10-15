//! `serve`: wires every module together and runs until SIGTERM or SIGINT.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{EXIT_FAILURE, EXIT_USAGE, git_runner, load_validated, print_problems};
use crate::auth::{AuthEvent, AuthState, MetricsHook, Throttle};
use crate::config::LogFormat;
use crate::http::{self, AdminState, PublicState};
use crate::keys::KeyStore;
use crate::logging;
use crate::metrics::Metrics;
use crate::paths::DenyList;
use crate::proc::Workers;
use crate::puller::{Puller, PullerDeps, ResolvedCreds};
use crate::scan::{GitleaksScanner, Scanner};
use crate::snapshot::Registry;
use crate::tools::Explorer;

const WORKERS_GAUGE_EVERY: Duration = Duration::from_secs(5);
const PULLER_STOP_GRACE: Duration = Duration::from_secs(10);

pub(super) async fn run(config_path: &Path, log_format: Option<LogFormat>) -> u8 {
    let cfg = match load_validated(config_path) {
        Ok(c) => Arc::new(c),
        Err(code) => return code,
    };
    if print_problems(&cfg.validate_binaries()) > 0 {
        return EXIT_USAGE;
    }
    logging::init(log_format.unwrap_or(cfg.logging.format), None);

    let (mut sigterm, mut sigint) = match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(t), Ok(i)) => (t, i),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("cannot install signal handlers: {e}");
            return EXIT_FAILURE;
        }
    };

    let repo_ids: Vec<String> = cfg.repo.iter().map(|r| r.id.clone()).collect();
    let keys = match KeyStore::new(cfg.auth.keys_file.clone(), repo_ids) {
        Ok(k) => k,
        Err(problems) => {
            eprintln!("{problems}");
            return EXIT_USAGE;
        }
    };
    let deny = match DenyList::new(cfg.deny.use_defaults, &cfg.deny.paths, &cfg.deny.allow) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!("{}: deny: {e}", config_path.display());
            return EXIT_USAGE;
        }
    };
    let creds = match ResolvedCreds::prepare(&cfg) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("cannot prepare credentials: {e}");
            return EXIT_FAILURE;
        }
    };

    let public_listener = match bind(cfg.server.listen).await {
        Ok(l) => l,
        Err(code) => return code,
    };
    let admin_listener = match bind(cfg.server.admin_listen).await {
        Ok(l) => l,
        Err(code) => return code,
    };
    let (Ok(public_addr), Ok(admin_addr)) =
        (public_listener.local_addr(), admin_listener.local_addr())
    else {
        eprintln!("cannot read the bound listener addresses");
        return EXIT_FAILURE;
    };

    let cancel = CancellationToken::new();
    keys.clone().watch();
    let metrics = Metrics::new();
    let workers = Workers::new(cfg.limits.max_concurrent_workers, cfg.limits.queue_timeout);
    let git = Arc::new(git_runner(&cfg));
    let scanner: Arc<dyn Scanner> =
        Arc::new(GitleaksScanner::new(cfg.scanner_bin(), cfg.scan.timeout));
    let registry = Arc::new(Registry::new(&cfg));
    spawn_workers_gauge(metrics.clone(), workers.clone(), cancel.clone());

    let explorer = Explorer::new(
        cfg.clone(),
        registry.clone(),
        workers,
        git.clone(),
        deny,
        metrics.clone(),
    );
    let puller_handles = Puller::spawn(PullerDeps {
        config: cfg.clone(),
        registry: registry.clone(),
        git,
        scanner,
        creds,
        cancel: cancel.clone(),
    });

    let throttle = Arc::new(Throttle::new(&cfg.auth.failed_attempts));
    let auth = Arc::new(AuthState {
        keys: keys.clone(),
        throttle: throttle.clone(),
        trusted: cfg.server.trusted_proxies.clone(),
        header: cfg.server.client_ip_header.clone(),
        metrics_hook: Some(auth_hook(metrics.clone(), throttle.clone())),
    });
    let public = http::public_router(
        explorer,
        PublicState {
            auth,
            allowed_origins: cfg.server.allowed_origins.clone(),
            metrics: metrics.clone(),
        },
    );
    let admin = http::admin_router(AdminState {
        cfg: cfg.clone(),
        registry,
        keys: keys.clone(),
        metrics,
        started_at: Utc::now(),
        throttle: Some(throttle),
    });
    let mut public_task = tokio::spawn(http::serve(public_listener, public, cancel.clone()));
    let mut admin_task = tokio::spawn(http::serve(admin_listener, admin, cancel.clone()));

    tracing::info!(
        event = "started",
        version = env!("CARGO_PKG_VERSION"),
        listen = %public_addr,
        admin_listen = %admin_addr,
        repos = cfg.repo.len(),
        keys = keys.count(),
    );

    let mut code = 0;
    tokio::select! {
        _ = sigterm.recv() => tracing::info!(event = "stopping", signal = "SIGTERM"),
        _ = sigint.recv() => tracing::info!(event = "stopping", signal = "SIGINT"),
        r = &mut public_task => {
            code = EXIT_FAILURE;
            report_listener_exit("public", r);
        }
        r = &mut admin_task => {
            code = EXIT_FAILURE;
            report_listener_exit("admin", r);
        }
    }
    cancel.cancel();

    let _ = public_task.await;
    let _ = admin_task.await;
    let stopped = futures::future::join_all(puller_handles);
    if tokio::time::timeout(PULLER_STOP_GRACE, stopped)
        .await
        .is_err()
    {
        tracing::warn!("pullers did not stop within the grace period");
    }
    tracing::info!(event = "stopped", exit_code = code);
    code
}

async fn bind(addr: std::net::SocketAddr) -> Result<TcpListener, u8> {
    TcpListener::bind(addr).await.map_err(|e| {
        eprintln!("cannot listen on {addr}: {e}");
        EXIT_FAILURE
    })
}

fn report_listener_exit(name: &str, r: Result<std::io::Result<()>, tokio::task::JoinError>) {
    match r {
        Ok(Ok(())) => tracing::error!(listener = name, "listener stopped unexpectedly"),
        Ok(Err(e)) => tracing::error!(listener = name, error = %e, "listener failed"),
        Err(e) => tracing::error!(listener = name, error = %e, "listener task panicked"),
    }
}

fn auth_hook(metrics: Arc<Metrics>, throttle: Arc<Throttle>) -> MetricsHook {
    Arc::new(move |event| {
        match event {
            AuthEvent::Failed { reason } => metrics.auth_failure(reason),
            AuthEvent::Blocked => metrics.auth_failure("blocked"),
            AuthEvent::Ok => return,
        }
        metrics.set_blocked_ips(throttle.blocked_count());
    })
}

fn spawn_workers_gauge(
    metrics: Arc<Metrics>,
    workers: Arc<Workers>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(WORKERS_GAUGE_EVERY);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tick.tick() => metrics.set_workers_busy(workers.busy()),
            }
        }
    })
}
