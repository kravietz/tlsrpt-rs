//use json::JsonValue::String;

use clap::{Parser, Subcommand};
use cluFlock::ToFlock;
use std::env;
use std::fs::OpenOptions;
use std::io::Read;
use tlsrpt::find_tlsrpt;
use tlsrpt::TlsRpt;
use tlsrpt::{save_tlsrpt, TlsRptStats};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[clap(short = 'v', long = "verbose")]
    verbose: bool,
    #[clap(short = 'd', long = "debug")]
    debug: bool,
    /// location of the status file
    #[clap(short = 'b', long = "db", default_value = "./tlsrpt-status.json")]
    db: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse TLS-RPT from JSON or RFC5322 email
    Parse {
        /// do not update status file
        #[clap(short = 'n', long = "no-write")]
        no_write: bool,
    },
    /// Parse TLS-RPT from IMAP server
    Imap {
        /// IMAP server hostname - username and password must be passed in environment vars USER and PASSWORD
        #[clap(short = 's', long = "server")]
        server: String,
        /// IMAP port
        #[clap(short = 'p', long = "port", default_value = "993")]
        port: u16,
        /// do not update status file
        #[clap(short = 'n', long = "no-write")]
        no_write: bool,
        #[clap(short = 'm', long = "mailbox", default_value = "INBOX")]
        mailbox: String,
    },
    /// Summarize reports seen previously
    Report,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Parse { no_write } => {
            let mut input = String::new();
            let mut stdin = std::io::stdin();

            stdin.read_to_string(&mut input).unwrap();

            let tls_rpt: TlsRpt = find_tlsrpt(input).expect("No TLS-RPT found in input");

            if cli.verbose {
                eprintln!("Found TLS report: {}", tls_rpt.report_id);
            }
            if cli.debug {
                eprintln!("{:#?}", tls_rpt);
            }

            if !*no_write {
                save_tlsrpt(cli.db.clone(), tls_rpt, cli.verbose, cli.debug);
            }
        }

        Commands::Report => {
            let db_file = cli.db.clone();
            let mut file_lock = OpenOptions::new()
                .read(true).open(db_file)
                .unwrap().wait_exclusive_lock().unwrap();
            let mut status_input = String::new();
            file_lock.read_to_string(&mut status_input).unwrap();

            let status: TlsRptStats = serde_json::from_str(&status_input).unwrap();

            if cli.debug {
                eprintln!("Status file {:?}", file_lock);
                eprintln!("Status = {:#?}", status);
            }

            if cli.verbose {
                println!("Reading {} reports", status.timeline.len());
            }

            let mut total_success: u32 = 0;
            let mut total_fail: u32 = 0;

            for report in status.reports.values() {
                for policy in report.policies.iter() {
                    total_success += policy.summary.total_successful_session_count;
                    total_fail += policy.summary.total_failure_session_count;

                    if cli.verbose || policy.summary.total_failure_session_count > 0 {
                        println!("{:?}\t{}\t{} failures\t{} successes\t{} {}",
                                 policy.policy.policy_type, policy.policy.policy_domain, policy.summary.total_failure_session_count,
                                 policy.summary.total_successful_session_count, report.organization_name, report.date_range.start_datetime);
                        match &policy.failure_details {
                            Some(failure_details) => {
                                for failure in failure_details {
                                    let additional_information = match &failure.additional_information {
                                        Some(value) => format!("Additional information: {}", value.to_string()),
                                        None => "".to_string(),
                                    };
                                    let failure_code = match &failure.failure_reason_code {
                                        Some(value) => format!("Failure code: {}", value.to_string()),
                                        None => "".to_string(),
                                    };
                                    println!("\t{:?}\tMX\t{}\t{}\t{}", failure.result_type, failure.receiving_mx_hostname, failure_code, additional_information);
                                }
                            }
                            None => {}
                        }
                    }
                }
            }

            println!("\nTotal success {}, total failures {}", total_success, total_fail);
        }

        Commands::Imap { server, no_write, port, mailbox } => {
            let user = env::var("USER").expect("missing environment variable USER required for IMAP login");
            let password = env::var("PASSWORD").expect("missing environment variable PASSWORD required for IMAP login");
            let client = imap::ClientBuilder::new(&server, *port).connect().unwrap();
            let mut imap_session = client.login(&user, &password).map_err(|e| e.0).unwrap();
            imap_session.select(mailbox).unwrap();
            // IMAP query relies on TLS-Report-Domain header per https://datatracker.ietf.org/doc/html/rfc8460#section-5.3
            let res = imap_session.search("HEADER \"TLS-Report-Domain\" \"\"").unwrap();

            if cli.debug {
                eprintln!("TLS-RPT emails found in IMAP mailbox: {:#?}", res);
            }

            for r in res.iter() {
                let messages = imap_session.fetch(r.to_string(), "RFC822").unwrap();
                for message in messages.iter() {
                    if let Some(mut body) = message.body() {
                        let mut bs = String::new();
                        body.read_to_string(&mut bs).unwrap();
                        if cli.debug {
                            println!("Email body:\n {}", bs);
                        }
                        let tls_rpt: TlsRpt = find_tlsrpt(bs).expect("No TLS-RPT found in input");
                        if cli.verbose {
                            eprintln!("Found TLS report: {}", tls_rpt.report_id);
                        }
                        if cli.debug {
                            eprintln!("TLS-RPT:\n{:#?}", tls_rpt);
                        }

                        if !*no_write {
                            save_tlsrpt(cli.db.clone(), tls_rpt, cli.verbose, cli.debug);
                        }
                    } else {
                        println!("Message didn't have a body!");
                    }
                }
                break;
            }

            imap_session.logout().unwrap();
        }
    }
}

