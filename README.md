# tlsrpt-rs

Rust library and utility to parse [SMTP TLS Reports (RFC8460)](https://datatracker.ietf.org/doc/html/rfc8460).

## Features

* Parse SMTP TLS reports from JSON and RFC822 email
* Filter and pull SMTP TLS report emails over IMAP
* Produce summary reports of reports parsed over a period

## Quickstart
The following assumes you've got [MTA-STS (RFC 8461)](https://datatracker.ietf.org/doc/html/rfc8461) set up using, for example, this
[NCSC MTA-STS guide](https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing/using-mta-sts-to-protect-the-privacy-of-your-emails).

Verify:
```angular2html
$ dig txt _mta-sts.krvtz.net +short
"v=STSv1; id=202406081231;"
$ curl https://mta-sts.krvtz.net/.well-known/mta-sts.txt
version: STSv1
mode: enforce
max_age: 10368000
mx: carp-20.krvtz.net
$ dig txt _smtp._tls.krvtz.net +short
"v=TLSRPTv1;rua=mailto:tlsrpt@example.com"
```
Note the last record - this is the mailbox where SMTP TLS reports will be sent to, and from where you want them pulled
from. It can be any email provider with IMAP support but it needs to be _outside_ of the your MTA-STS protected domain.

Install the binary (you need a working [Rust compiler](https://www.rust-lang.org/tools/install)):

```angular2html
$ cargo install --git https://git.sr.ht/~kravietz/tlsrpt-rs tlsrpt
```
Binaries end up in `~/.cargo/bin`, so you may want to update your shell's `PATH` variable.

Add to `crontab`:

```angular2html
$ crontab -e
# add the following
@hourly env IMAP_USER=tlsrpt@example.com IMAP_PASS=… /home/user/.cargo/bin/tlsrpt imap --server imap.example.com
@hourly /home/user/.cargo/bin/tlsrpt report 2>/dev/null
@weekly /home/user/.cargo/bin/tlsrpt --verbose report
```
Routine _success_ reports will be recorded but produce no reports. Any _failure_ report will produce an alert email,
plus there's a weekly summary of all success and failure alerts over the whole period. To reset statistics, simply
remove the `tlsprt.json` file.

## Commands summary

* `parse`   Parse TLS-RPT from JSON or RFC5322 email
* `imap`    Parse TLS-RPT from IMAP server
* `report`  Summarize reports seen previously

Options:

```
  -v, --verbose  
  -d, --debug    
  -b, --db <DB>  location of the status file [default: tlsrpt.json]
```
Note the generic options (e.g. `--debug`) are placed _before_ the action command (e.g. `parse`).

## Command `parse`

Parse a SMTP TLS report on standard input with auto-detection of JSON (raw report) or RFC822 (gzipped JSON attachment
embedded in an `.eml` file).  Reports and their timeline are written to a local database file (default: `./tlsrpt.json`)
for further use by `tlsrpt report`.  This command can be used in scripts, for manual parsing of reports or placing
in a mailer pipeline (e.g. `/etc/aliases`). With these use cases in mind, the command produces no output by default,
except for errors. With `--verbose` it will display the report id, with `--debug` it will pretty-print detailed
report structure. 


Options:
```
-n, --no-write             do not update status file
```

Examples:

```
$ tlsrpt --verbose parse --no-write < tlsrpt/fixtures/mail.ru.eml
Found TLS report: c96d67df-0440-57f7-6e96-c83824d0fdf2@mail.ru
$  tlsrpt --debug parse --no-write < tlsrpt/fixtures/mail.ru.eml
TlsRpt {
    organization_name: "Mail.ru",
    date_range: TlsRptDateRange {
        start_datetime: 2023-01-25 0:00:00.0 +00:00:00,
        end_datetime: 2023-01-26 0:00:00.0 +00:00:00,
    …
```

## Command `imap`

Fetch SMTP TLS report emails from an IMAP mailbox. IMAP server parameters can be specified with either command line
options or environmental variables (especially suitable for credentials) but command-line options take precedence
over environment variables. The use case is the `rua=mailto:reports@example.com` reporting policy per
[RFC 8460 3.1.1](https://datatracker.ietf.org/doc/html/rfc8460#section-3.1.1) where a third-party domain is being
used for receiving the reports because when your primary email domain
[MTA-STS](https://datatracker.ietf.org/doc/html/rfc8461) is broken no reports will arrive there in the first place.

```
  -s, --server <SERVER>      IMAP server hostname [env: IMAP_SERVER=]
  -U, --username <USERNAME>  IMAP username [env: IMAP_USER=]
  -P, --password <PASSWORD>  IMAP password [env: IMAP_PASS=]
  -m, --mailbox <MAILBOX>    IMAP mailbox [env: IMAP_MAILBOX=] [default: INBOX]
  -p, --port <PORT>          IMAP port [env: IMAP_PORT=] [default: 993]
  -f, --filter <FILTER>      Find TLSRPT emails in mailbox using header (faster, but not supported by all IMAP servers)
                             or by subject (slower, subject to false positives) [default: header] [possible values: header, subject]
  -n, --no-write             do not update status file
````

Per [RFC 8460](https://datatracker.ietf.org/doc/html/rfc8460) each SMTP TLS report email should contain 
a `TLS-Report-Domain` header, which significantly simplifies searching for such reports in the IMAP mailbox. For
IMAP servers that do not support header search there's a fallback method selected using `--filter=subject` which
will search for emails with subject starting with `Report Domain:`.

Examples:

```
$ env IMAP_USER=user@example.com IMAP_PASS="…" \
    tlsrpt --verbose imap --server imap.example.com --port 993
Found TLS report: 2024-09-18T00:00:00Z_krvtz.net
Found TLS report: 2024-09-13T00:00:00Z_krvtz.net
Found TLS report: 2024-09-15T00:00:00Z_krvtz.net
Found TLS report: 133725431418780496+krvtz.net
Found TLS report: 2024-09-19T00:00:00Z_krvtz.net
Found TLS report: 133708152202987951+krvtz.net
```

## Command `report`

Read the status file (default: `tlsrpt.json`) and alert about any failures only. When `--verbose` options is passed,
the summary also displays successful reports. This command is intended to be run manually or from `cron`, producing
an email in case of a reported TLS failure.

Example:

```
$ tlsrpt --verbose report
Reading 26 reports
Sts	krvtz.net	0 failures	2 successes	Google Inc. 2024-09-23 0:00:00.0 +00:00:00
Sts	krvtz.net	1 failures	0 successes	Mail.ru 2023-01-25 0:00:00.0 +00:00:00
	StsPolicyFetchError	MX	None	Failure code: unable to do http request:
	Get "https://mta-sts.krvtz.net/.well-known/mta-sts.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)	
Sts	krvtz.net	0 failures	4 successes	Google Inc. 2024-09-30 0:00:00.0 +00:00:00
Sts	krvtz.net	0 failures	3 successes	Google Inc. 2024-09-25 0:00:00.0 +00:00:00
```

# License

[Big Time Public License 2.0.0](https://bigtimelicense.com/versions/2.0.0)