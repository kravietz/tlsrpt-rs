use cluFlock;
use cluFlock::ToFlock;
use flate2::read::GzDecoder;
use mail_parser::{MessageParser, MimeHeaders};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use std::net::IpAddr;
use time::OffsetDateTime;

#[derive(Serialize, Deserialize, Debug)]
pub struct TlsRptStats {
    /// chronological list of reports received
    pub timeline: Vec<String>,
    /// individual reports are stored here referred by policy
    pub reports: HashMap<String, TlsRpt>,
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
    policy_string: Vec<String>,
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
    pub sending_mta_ip: IpAddr,
    pub receiving_mx_hostname: String,
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

pub fn save_tlsrpt(db_file: String, tls_rpt: TlsRpt, verbose: bool, debug: bool) {
    // prepare to update local status file
    let mut file_lock = OpenOptions::new()
        .create(true).write(true).read(true).open(db_file)
        .unwrap().wait_exclusive_lock().unwrap();
    let mut status_input = String::new();

    file_lock.read_to_string(&mut status_input).unwrap();

    // read JSON status and return blank template if failed (non-existent etc)
    let mut status: TlsRptStats = serde_json::from_str(&status_input).unwrap_or_else(|e| {
        if verbose {
            eprintln!("Error while reading old status (ignored): {:?}", e);
        }
        TlsRptStats { timeline: Vec::new(), reports: HashMap::new() }
    });

    let report_id = tls_rpt.report_id.clone();

    if status.reports.contains_key(&report_id) {
        if verbose { eprintln!("The report {report_id} is already processed, skipping."); }
        return;
    }
    status.reports.insert(report_id.clone(), tls_rpt.clone());
    status.timeline.push(report_id.clone());

    if debug {
        eprintln!("Writing status to file {:?}", file_lock);
    }

    let output = serde_json::to_string(&status).unwrap();

    if debug {
        eprintln!("New serialized status: {}", output);
    }

    file_lock.rewind().unwrap();
    file_lock.write(&output.as_bytes()).unwrap();
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
}