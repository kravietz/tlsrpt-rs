//use json::JsonValue::String;

use clap::{Parser, Subcommand, ValueEnum};
use std::io::Read;
use tlsrpt::{find_tlsrpt, save_tlsrpt, read_status_file, write_status_file, TlsRpt};

#[derive(ValueEnum, Clone, Debug)]
enum ImapFilter {
    Header,
    Subject,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[clap(short = 'v', long = "verbose")]
    verbose: bool,
    #[clap(short = 'd', long = "debug")]
    debug: bool,
    /// location of the status file
    #[clap(short = 'b', long = "db", default_value = "tlsrpt.json")]
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
        /// IMAP server hostname
        #[clap(short = 's', long = "server", env = "IMAP_SERVER", required = true)]
        server: String,
        /// IMAP username
        #[clap(short = 'U', long = "username", env = "IMAP_USER", required = true)]
        username: String,
        /// IMAP password
        #[clap(short = 'P', long = "password", env = "IMAP_PASS", required = true)]
        password: String,
        /// IMAP mailbox
        #[clap(
            short = 'm',
            long = "mailbox",
            default_value = "INBOX",
            env = "IMAP_MAILBOX"
        )]
        mailbox: String,
        /// IMAP port
        #[clap(short = 'p', long = "port", default_value = "993", env = "IMAP_PORT")]
        port: u16,
        /// Find TLSRPT emails in mailbox using header (faster, but not supported by all IMAP
        /// servers) or by subject (slower, subject to false positives)
        #[clap(short = 'f', long = "filter", value_enum, default_value_t = ImapFilter::Header)]
        filter: ImapFilter,
        /// do not update status file
        #[clap(short = 'n', long = "no-write")]
        no_write: bool,
        /// by default only NEW messages are fetched from IMAP, this option fetches all messages,
        /// including historic messages fetched before
        #[clap(short = 'a', long = "all-messages", default_value_t = false)]
        all_messages: bool,
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

            // no write option is off, so update the status file
            if !*no_write {
                save_tlsrpt(cli.db.clone(), tls_rpt, cli.verbose, cli.debug);
            }
        }

        Commands::Report => {
            let mut status = read_status_file(cli.db.clone(), cli.verbose, cli.debug);
            
            if cli.debug {
                eprintln!("Status = {:#?}", status);
            }

            if cli.verbose {
                println!("Reading {} reports", status.timeline.len());
            }

            let mut total_success: u32 = 0;
            let mut total_fail: u32 = 0;
            let mut status_was_updated = false;

            for report in status.reports.values() {
                for policy in report.policies.iter() {
                    total_success += policy.summary.total_successful_session_count;
                    total_fail += policy.summary.total_failure_session_count;

                    // record are only printed when:
                    // 1) when verbose mode is enabled
                    // 2) OR  report is failed
                    // 3)     AND report has not been printed previously
                    // by default, success reports are *not* printed
                    if cli.verbose ||
                        (policy.summary.total_failure_session_count > 0 &&
                            !status.reported.contains(&report.report_id)) {
                        // print report header detailing report type, sender, date e.g.
                        // Sts	krvtz.net	9 failures	0 successes	Google Inc. 2025-06-01 0:00:00.0 +00:00:00
                        println!(
                            "{:?}\t{}\t{} failures\t{} successes\t{} {}",
                            policy.policy.policy_type,
                            policy.policy.policy_domain,
                            policy.summary.total_failure_session_count,
                            policy.summary.total_successful_session_count,
                            report.organization_name,
                            report.date_range.start_datetime
                        );
                        // record that this policy_id was already reported
                        status.reported.push(report.report_id.clone());
                        status_was_updated  = true;
                        // fail-safe when failure_details fields is not present
                        match &policy.failure_details {
                            Some(failure_details) => {
                                for failure in failure_details {
                                    let additional_information = match &failure
                                        .additional_information
                                    {
                                        Some(value) => {
                                            format!("Additional information: {}", value.to_string())
                                        }
                                        None => "".to_string(),
                                    };
                                    let failure_code = match &failure.failure_reason_code {
                                        Some(value) => {
                                            format!("Failure code: {}", value.to_string())
                                        }
                                        None => "".to_string(),
                                    };
                                    // display indented line for each specific failure e.g.
                                    // CertificateNotTrusted	MX	Some("carp-20.krvtz.net")
                                    println!(
                                        "\t{:?}\tMX\t{:?}\t{}\t{}",
                                        failure.result_type,
                                        failure.receiving_mx_hostname,
                                        failure_code,
                                        additional_information
                                    );
                                }
                            }
                            None => {}
                        }
                    }
                }
            }
            
            if status_was_updated {
                write_status_file(cli.db.clone(), status, cli.verbose, cli.debug);
            }

            if cli.verbose {
                println!(
                    "\nTotal success {}, total failures {}",
                    total_success, total_fail
                );
            }
        }

        Commands::Imap {
            server,
            no_write,
            port,
            mailbox,
            username,
            password,
            filter,
            all_messages,
        } => {
            if cli.debug {
                eprintln!(
                    "Attempting IMAP login user={:#?} server={:#?}",
                    username, server
                );
            }

            let client = imap::ClientBuilder::new(&server, *port).connect().unwrap();

            let mut imap_session = client.login(&username, &password).map_err(|e| e.0).unwrap();
            imap_session.select(mailbox).unwrap();

            // IMAP query relies on TLS-Report-Domain header per https://datatracker.ietf.org/doc/html/rfc8460#section-5.3
            let imap_query: String;
            let imap_new = if *all_messages {
                "" // all_messages enabled - fetch historic messages
            } else {
                "NEW " // default - only fetch new messages
            }
            .to_string();

            // IMAP SEARCH query syntax https://tools.ietf.org/html/rfc3501#section-6.4.4
            match filter {
                ImapFilter::Header => {
                    imap_query = format!("{imap_new}HEADER \"TLS-Report-Domain\" \"\"");
                }
                ImapFilter::Subject => {
                    imap_query = format!("{imap_new}SUBJECT \"Report Domain:\"");
                }
            }

            if cli.debug {
                eprintln!("IMAP filter={:#?}", imap_query);
            }

            let res = imap_session.search(imap_query).unwrap();

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
                            eprintln!("Email body:\n {}", bs);
                        }
                        let tls_rpt: TlsRpt = find_tlsrpt(bs).expect("No TLS-RPT found in input");
                        if cli.verbose {
                            eprintln!("Found TLS report: {}", tls_rpt.report_id);
                        }
                        if cli.debug {
                            eprintln!("TLS-RPT:\n{:#?}", tls_rpt);
                        }

                        // no write option is off, so update the status file
                        if !*no_write {
                            save_tlsrpt(cli.db.clone(), tls_rpt, cli.verbose, cli.debug);
                        }
                    } else {
                        if cli.debug {
                            eprintln!("Message didn't have a body!");
                        }
                    }
                }
            }

            imap_session.logout().unwrap();
        }
    }
}
