use cluFlock;
use cluFlock::ToFlock;
use flate2::read::GzDecoder;
use mail_parser::{MessageParser, MimeHeaders};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::IpAddr;
use time::OffsetDateTime;

#[derive(Serialize, Deserialize, Debug)]
pub struct TlsRptStats {
    /// chronological list of report_ids in the order received
    pub timeline: Vec<String>,
    /// full reports are stored here referred by their report_id 
    pub reports: HashMap<String, TlsRpt>,
    /// report_ids of reports that have been already reported to avoid sending repeated reports
    pub reported: Vec<String>,
}

// TLS-RPT https://datatracker.ietf.org/doc/html/rfc8460
// Report format defined in HPKP https://datatracker.ietf.org/doc/html/rfc7469#section-3

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum TlsRptPolicyType {
    Sts,
    Tlsa,
    NoPolicyFound,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct TlsRptPolicyWrapper {
    pub policy: TlsRptPolicy,
    pub summary: TlsRptSummary,
    pub failure_details: Option<Vec<TlsRptFailureDetails>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct TlsRptPolicy {
    pub policy_type: TlsRptPolicyType,
    // per RFC this is not optional, but at least mail.ru sends reports without this field
    pub policy_string: Option<Vec<String>>,
    pub policy_domain: String,
    mx_host: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct TlsRptSummary {
    pub total_successful_session_count: u32,
    pub total_failure_session_count: u32,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
#[serde_as]
pub struct TlsRptDateRange {
    #[serde(with = "time::serde::iso8601")]
    pub start_datetime: OffsetDateTime,
    #[serde(with = "time::serde::iso8601")]
    pub end_datetime: OffsetDateTime,
}

// https://datatracker.ietf.org/doc/html/rfc8460#section-6.6
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum TlsRptFailureResultType {
    StarttlsNotSupported,
    CertificateHostMismatch,
    CertificateExpired,
    TlsaInvalid,
    DnssecInvalid,
    DaneRequired,
    CertificateNotTrusted,
    StsPolicyInvalid,
    StsWebpkiInvalid,
    ValidationFailure,
    StsPolicyFetchError,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct TlsRptFailureDetails {
    pub result_type: TlsRptFailureResultType,
    pub sending_mta_ip: Option<IpAddr>,
    pub receiving_mx_hostname: Option<String>,
    pub receiving_mx_helo: Option<String>,
    pub receiving_ip: Option<IpAddr>,
    pub failed_session_count: u32,
    pub additional_information: Option<String>,
    pub failure_reason_code: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct TlsRpt {
    pub organization_name: String,
    pub date_range: TlsRptDateRange,
    pub contact_info: String,
    pub report_id: String,
    pub policies: Vec<TlsRptPolicyWrapper>,
}

// find TLS-RPT in email attachment, guessing if it's ZIP, GZ or raw JSON
pub fn find_tlsrpt(input: String) -> Option<TlsRpt> {
    // try to tlsrpt as JSON - check if raw TLS-RPT was passed on input
    if input.starts_with("{") { // dummy JSON detection heuristics
        Some(serde_json::from_str(&input).expect("Incompatible TLS-RPT format"))
    } else {
        // try to tlsrpt stdin as RFC5322 email extracting JSON attachment
        let message = MessageParser::default().parse(input.as_bytes()).unwrap();

        for attachment in message.attachments() {
            let attachment_name = attachment.attachment_name().unwrap();

            // find likely TLS-RPT attachment, RFC allows both .json.gz and .json
            if attachment_name.ends_with(".json.gz") {
                let body = attachment.contents();
                let mut gzip = GzDecoder::new(body);
                let mut json = String::new();
                // this is redundant but allows detection of gzip errors
                gzip.read_to_string(&mut json).expect("Failed to decompress gzipped attachment");
                return Some(serde_json::from_str(json.as_str()).expect("Incompatible TLS-RPT format"));
            } else if attachment_name.ends_with(".json") {
                let body = attachment.contents();
                return Some(serde_json::from_reader(body).expect("Failed to tlsrpt JSON attachment"));
            }
        }
        // no attachments found
        None
    }
}

pub fn read_status_file(db_file: String, verbose: bool, debug: bool) -> TlsRptStats {
    let mut status: TlsRptStats = TlsRptStats { timeline: Vec::new(), reports: HashMap::new(), reported: Vec::new() };

    let file = File::open(db_file);
    match file {
        Err(_) => {
            // file did not exist, return empty
            status
        },
        Ok(file) => {
            let mut input : String = String::new();

            file.wait_exclusive_lock().unwrap().read_to_string(&mut input).unwrap();

            // read JSON status and return blank template if failed (malformed etc)
            status = serde_json::from_str(&input).unwrap_or_else(|e| {
                if verbose {
                    eprintln!("Error while reading old status (ignored): {:?}", e);
                    if debug {
                        eprintln!("Old status: {:?}", input);
                    }
                }
                status // deserialisation failed, return empty
            });
            status // deserialisation, return actual status
        }
    }
}

pub fn write_status_file(db_file: String, status: TlsRptStats, _verbose: bool, debug: bool) {
    let output = serde_json::to_string(&status).unwrap();

    if debug {
        eprintln!("New serialized status: {}", output);
    }

    let mut file = File::create(db_file).unwrap().wait_exclusive_lock().unwrap();

    if debug {
        eprintln!("Writing status to file {:?}", file);
    }
    file.write(&output.as_bytes()).unwrap();
}

pub fn save_tlsrpt(status_file : String, tls_rpt: TlsRpt, verbose: bool, debug: bool) {
    let mut status = read_status_file(status_file.clone(), verbose, debug);
    let report_id = tls_rpt.report_id.clone();
    
    // deduplication
    if status.reports.contains_key(&report_id) {
        if verbose { eprintln!("The report {report_id} is already processed, skipping."); }
        return;
    }
    status.reports.insert(report_id.clone(), tls_rpt.clone());
    status.timeline.push(report_id.clone());

    write_status_file(status_file.clone(), status, verbose, debug);
    
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_find_tlsrpt_1() {
        let input = std::fs::read_to_string("fixtures/google1.eml").unwrap();
        find_tlsrpt(input).unwrap();
    }
    #[test]
    fn test_find_tlsrpt_2() {
        let input = std::fs::read_to_string("fixtures/google2.eml").unwrap();
        find_tlsrpt(input).unwrap();
    }
    #[test]
    fn test_find_tlsrpt_3() {
        let input = std::fs::read_to_string("fixtures/microsoft1.eml").unwrap();
        find_tlsrpt(input).unwrap();
    }
    #[test]
    fn test_find_tlsrpt_4() {
        let input = std::fs::read_to_string("fixtures/rfc8460.json").unwrap();
        find_tlsrpt(input).unwrap();
    }
    #[test]
    #[should_panic]
    fn test_find_tlsrpt_5() {
        let input = std::fs::read_to_string("fixtures/empty.eml").unwrap();
        find_tlsrpt(input).unwrap();
    }
    #[test]
    fn test_find_tlsrpt_6() {
        let input = std::fs::read_to_string("fixtures/mail.ru.eml").unwrap();
        find_tlsrpt(input).unwrap();
    }
}