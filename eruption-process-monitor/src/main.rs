/*
    This file is part of Eruption.

    Eruption is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Eruption is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Eruption.  If not, see <http://www.gnu.org/licenses/>.
*/

use clap::Clap;
use clap::*;
use crossbeam::channel::{select, unbounded, Receiver, Sender};
use hotwatch::{
    blocking::{Flow, Hotwatch},
    Event,
};
use lazy_static::lazy_static;
use log::*;
use parking_lot::Mutex;
use procmon::ProcMon;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap, env, fs, path::Path, path::PathBuf, sync::atomic::AtomicBool, sync::Arc,
};
use std::{sync::atomic::Ordering, thread, time::Duration};

mod constants;
mod dbus_client;
mod manifest;
mod process;
mod procmon;
mod util;

lazy_static! {
    /// Global configuration
    pub static ref CONFIG: Arc<Mutex<Option<config::Config>>> = Arc::new(Mutex::new(None));

    /// Mapping between process event => action
    pub static ref PROCESS_EVENT_MAP: Arc<Mutex<HashMap<String, Action>>> = Arc::new(Mutex::new(HashMap::new()));

    // Flags

    /// Global "enable experimental features" flag
    pub static ref EXPERIMENTAL_FEATURES: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

    /// Global "quit" status flag
    pub static ref QUIT: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
}

type Result<T> = std::result::Result<T, eyre::Error>;

#[derive(Debug, thiserror::Error)]
pub enum MainError {
    #[error("Unknown error: {description}")]
    UnknownError { description: String },

    #[error("Could not register Linux process monitoring")]
    ProcMonError {},

    #[error("Could not switch profiles")]
    SwitchProfileError {},
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    SwitchToProfile { profile_name: String },
    SwitchToSlot { slot_index: usize },
}

#[derive(Debug, Clone)]
pub enum SystemEvent {
    ProcessExec {
        event: procmon::Event,
        file_name: Option<String>,
    },
    ProcessExit {
        event: procmon::Event,
        file_name: Option<String>,
    },
}

/// Supported command line arguments
#[derive(Debug, Clap)]
#[clap(
    version = env!("CARGO_PKG_VERSION"),
    author = "X3n0m0rph59 <x3n0m0rph59@gmail.com>",
    about = "A CLI utility to monitor and introspect system processes",
)]
pub struct Options {
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[clap(short, long, parse(from_occurrences))]
    verbose: u8,

    /// Sets the configuration file to use
    #[clap(short, long)]
    config: Option<String>,

    #[clap(subcommand)]
    command: Subcommands,
}

// Subcommands
#[derive(Debug, Clap)]
pub enum Subcommands {
    /// Run in background and monitor running processes
    Daemon,
    /// Introspect process with PID
    Introspect {
        pid: i32,
    },

    ListRules,

    RuleAdd {
        rule: Vec<String>,
    },

    RuleRemove {
        index: usize,
    },
}

#[derive(Debug, Clone)]
pub enum FileSystemEvent {
    RulesChanged,
}

/// Print license information
#[allow(dead_code)]
fn print_header() {
    println!(
        r#"
 Eruption is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Eruption is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Eruption.  If not, see <http://www.gnu.org/licenses/>.
"#
    );
}

/// Process system related events
async fn process_system_events(event: &SystemEvent) -> Result<()> {
    // limit the number of messages that will be processed during this iteration
    let mut loop_counter = 0;

    'SYSTEM_EVENTS_LOOP: loop {
        let mut event_processed = false;

        match event {
            SystemEvent::ProcessExec {
                event: _,
                file_name,
            } => {
                if let Some(file_name) = file_name {
                    let exe = PathBuf::from(file_name);

                    match &PROCESS_EVENT_MAP.lock().get(&*exe.to_string_lossy()) {
                        Some(action) => match action {
                            Action::SwitchToProfile { profile_name } => {
                                info!("Switching to profile: {}", profile_name);

                                dbus_client::switch_profile(&profile_name).await?;
                            }

                            Action::SwitchToSlot { slot_index } => {
                                info!("Switching to slot: {}", slot_index);

                                dbus_client::switch_slot(*slot_index).await?;
                            }
                        },

                        None => {
                            // no matching rule
                        }
                    }
                } else {
                    warn!("Could not get executable file name");
                }

                event_processed = true;
            }

            SystemEvent::ProcessExit { event, file_name } => {
                event_processed = true;
            }
        }

        if !event_processed || loop_counter > constants::MAX_EVENTS_PER_ITERATION {
            break 'SYSTEM_EVENTS_LOOP; // no more events in queue or iteration limit reached
        }

        loop_counter += 1;
    }

    Ok(())
}

/// Process filesystem related events
async fn process_fs_events(event: &FileSystemEvent) -> Result<()> {
    // limit the number of messages that will be processed during this iteration
    let mut loop_counter = 0;

    'FS_EVENTS_LOOP: loop {
        let mut event_processed = false;

        match event {
            FileSystemEvent::RulesChanged => {
                warn!("Rules changed, reloading...");

                load_event_map()?;

                for (exe_file, action) in PROCESS_EVENT_MAP.lock().iter() {
                    debug!("{} => {:?}", exe_file, action);
                }

                event_processed = true;
            }
        }

        if !event_processed || loop_counter > constants::MAX_EVENTS_PER_ITERATION {
            break 'FS_EVENTS_LOOP; // no more events in queue or iteration limit reached
        }

        loop_counter += 1;
    }

    Ok(())
}

pub fn spawn_system_monitor_thread(sysevents_tx: Sender<SystemEvent>) -> Result<()> {
    thread::Builder::new()
        .name("monitor".to_owned())
        .spawn(move || -> Result<()> {
            let procmon = ProcMon::new()?;

            loop {
                // check if we shall terminate the thread
                if QUIT.load(Ordering::SeqCst) {
                    break Ok(());
                }

                // process procmon events
                let event = procmon.wait_for_event();
                match event.event_type {
                    procmon::EventType::Exec => {
                        let pid = event.pid;

                        sysevents_tx
                            .send(SystemEvent::ProcessExec {
                                event,
                                file_name: util::get_process_file_name(pid).ok(),
                            })
                            .unwrap_or_else(|e| error!("Could not send on a channel: {}", e));
                    }

                    procmon::EventType::Exit => {
                        let pid = event.pid;

                        sysevents_tx
                            .send(SystemEvent::ProcessExit {
                                event,
                                file_name: util::get_process_file_name(pid).ok(),
                            })
                            .unwrap_or_else(|e| error!("Could not send on a channel: {}", e));
                    }

                    _ => { /* ignore others */ }
                }
            }
        })?;

    Ok(())
}

/// Watch filesystem events
pub fn register_filesystem_watcher(
    fsevents_tx: Sender<FileSystemEvent>,
    config_file: PathBuf,
    rule_file: PathBuf,
) -> Result<()> {
    debug!("Registering filesystem watcher...");

    thread::Builder::new()
        .name("hotwatch".to_owned())
        .spawn(
            move || match Hotwatch::new_with_custom_delay(Duration::from_millis(1000)) {
                Err(e) => error!("Could not initialize filesystem watcher: {}", e),

                Ok(ref mut hotwatch) => {
                    hotwatch
                        .watch(config_file, move |_event: Event| {
                            info!("Configuration File changed on disk, please restart eruption-process-monitor for the changes to take effect!");

                            Flow::Continue
                        })
                        .unwrap_or_else(|e| error!("Could not register file watch: {}", e));


                    hotwatch
                        .watch(&rule_file, move |event: Event| {
                            debug!("Rule file changed: {:?}", event);

                            fsevents_tx.send(FileSystemEvent::RulesChanged).unwrap_or_else(|e| error!("Could not send on a channel: {}", e));

                            Flow::Continue
                        })
                        .unwrap_or_else(|e| error!("Could not register file watch: {}", e));


                    hotwatch.run();
                }
            },
        )?;

    Ok(())
}

#[cfg(debug_assertions)]
mod thread_util {
    use crate::Result;
    use log::*;
    use parking_lot::deadlock;
    use std::thread;
    use std::time::Duration;

    /// Creates a background thread which checks for deadlocks every 5 seconds
    pub(crate) fn deadlock_detector() -> Result<()> {
        thread::Builder::new()
            .name("deadlockd".to_owned())
            .spawn(move || loop {
                thread::sleep(Duration::from_secs(5));
                let deadlocks = deadlock::check_deadlock();
                if !deadlocks.is_empty() {
                    error!("{} deadlocks detected", deadlocks.len());

                    for (i, threads) in deadlocks.iter().enumerate() {
                        error!("Deadlock #{}", i);

                        for t in threads {
                            error!("Thread Id {:#?}", t.thread_id());
                            error!("{:#?}", t.backtrace());
                        }
                    }
                }
            })?;

        Ok(())
    }
}

pub async fn run_main_loop(
    sysevents_rx: &Receiver<SystemEvent>,
    fsevents_rx: &Receiver<FileSystemEvent>,
) -> Result<()> {
    trace!("Entering main loop...");

    'MAIN_LOOP: loop {
        if QUIT.load(Ordering::SeqCst) {
            break 'MAIN_LOOP;
        }

        select!(
            recv(sysevents_rx) -> message => process_system_events(&message?).await?,
            recv(fsevents_rx) -> message => process_fs_events(&message?).await?,
        );
    }

    Ok(())
}

fn load_event_map() -> Result<()> {
    let rules_file = PathBuf::from(constants::STATE_DIR).join("process-monitor.rules");

    let s = fs::read_to_string(&rules_file)?;
    let event_map = serde_json::from_str(&s)?;

    *PROCESS_EVENT_MAP.lock() = event_map;

    Ok(())
}

fn save_event_map() -> Result<()> {
    let rules_file = PathBuf::from(constants::STATE_DIR).join("process-monitor.rules");

    let s = serde_json::to_string_pretty(&*PROCESS_EVENT_MAP.lock())?;
    fs::write(&rules_file, s)?;

    Ok(())
}

#[tokio::main]
pub async fn main() -> std::result::Result<(), eyre::Error> {
    color_eyre::install()?;

    // if unsafe { libc::isatty(0) != 0 } {
    //     print_header();
    // }

    let opts = Options::parse();

    // start the thread deadlock detector
    #[cfg(debug_assertions)]
    thread_util::deadlock_detector()
        .unwrap_or_else(|e| error!("Could not spawn deadlock detector thread: {}", e));

    // initialize logging
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG_OVERRIDE", "info");
        pretty_env_logger::init_custom_env("RUST_LOG_OVERRIDE");
    } else {
        pretty_env_logger::init();
    }

    info!(
        "Starting eruption-process-monitor: Version {}",
        env!("CARGO_PKG_VERSION")
    );

    // register ctrl-c handler
    let q = QUIT.clone();
    ctrlc::set_handler(move || {
        q.store(true, Ordering::SeqCst);
    })
    .unwrap_or_else(|e| error!("Could not set CTRL-C handler: {}", e));

    // process configuration file
    let config_file = opts
        .config
        .unwrap_or_else(|| constants::PROCESS_MONITOR_CONFIG_FILE.to_string());

    let mut config = config::Config::default();
    config.merge(config::File::new(&config_file, config::FileFormat::Toml))?;

    *CONFIG.lock() = Some(config.clone());

    // enable support for experimental features?
    let enable_experimental_features = config
        .get::<bool>("global.enable_experimental_features")
        .unwrap_or(false);

    EXPERIMENTAL_FEATURES.store(enable_experimental_features, Ordering::SeqCst);

    if EXPERIMENTAL_FEATURES.load(Ordering::SeqCst) {
        warn!("** EXPERIMENTAL FEATURES are ENABLED, this may expose serious bugs! **");
    }

    info!("Loading rules...");
    load_event_map()?;

    match opts.command {
        Subcommands::Daemon => {
            for (exe_file, action) in PROCESS_EVENT_MAP.lock().iter() {
                debug!("{} => {:?}", exe_file, action);
            }

            let rules_file = PathBuf::from(constants::STATE_DIR).join("process-monitor.rules");

            let (fsevents_tx, fsevents_rx) = unbounded();
            register_filesystem_watcher(fsevents_tx, PathBuf::from(config_file), rules_file)?;

            let (sysevents_tx, sysevents_rx) = unbounded();
            spawn_system_monitor_thread(sysevents_tx)?;

            info!("Startup completed");

            debug!("Entering the main loop now...");

            // enter the main loop
            run_main_loop(&sysevents_rx, &fsevents_rx)
                .await
                .unwrap_or_else(|e| error!("{}", e));

            debug!("Left the main loop");
        }

        Subcommands::Introspect { pid: _ } => {}

        Subcommands::ListRules => {
            println!("Dumping rules:");

            for (exe_file, action) in PROCESS_EVENT_MAP.lock().iter() {
                println!("{} => {:?}", exe_file, action);
            }
        }

        Subcommands::RuleAdd { rule } => {
            if rule.len() != 2 {
                error!("Malformed rule definition");
            } else {
                let exe_file = String::from(&rule[0]);
                let profile_name = String::from(&rule[1]);

                PROCESS_EVENT_MAP.lock().insert(
                    exe_file,
                    Action::SwitchToProfile {
                        profile_name: profile_name,
                    },
                );
            }
        }

        Subcommands::RuleRemove { index } => {}
    }

    info!("Saving rules...");
    save_event_map()?;

    info!("Exiting now");

    Ok(())
}
