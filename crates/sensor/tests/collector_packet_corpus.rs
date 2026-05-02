use innerwarden_sensor::collectors::{dns_capture, http_capture, tls_fingerprint};

fn fixture(name: &str) -> Vec<u8> {
    let raw = match name {
        "dns_a_example_com.hex" => {
            include_str!("../testdata/pcap/dns_a_example_com.hex")
        }
        "dns_aaaa_innerwarden_dev.hex" => {
            include_str!("../testdata/pcap/dns_aaaa_innerwarden_dev.hex")
        }
        "dns_txt_long_subdomain.hex" => {
            include_str!("../testdata/pcap/dns_txt_long_subdomain.hex")
        }
        "dns_mx_mail_example.hex" => {
            include_str!("../testdata/pcap/dns_mx_mail_example.hex")
        }
        "http_get_root.hex" => include_str!("../testdata/pcap/http_get_root.hex"),
        "http_post_login.hex" => include_str!("../testdata/pcap/http_post_login.hex"),
        "http_get_env_probe.hex" => {
            include_str!("../testdata/pcap/http_get_env_probe.hex")
        }
        "tls_client_hello_example_h2.hex" => {
            include_str!("../testdata/pcap/tls_client_hello_example_h2.hex")
        }
        "tls_client_hello_innerwarden_http11.hex" => {
            include_str!("../testdata/pcap/tls_client_hello_innerwarden_http11.hex")
        }
        "tls_client_hello_no_sni.hex" => {
            include_str!("../testdata/pcap/tls_client_hello_no_sni.hex")
        }
        other => panic!("unknown packet fixture: {other}"),
    };
    decode_hex(raw)
}

fn decode_hex(raw: &str) -> Vec<u8> {
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(compact.len() % 2, 0, "hex fixture must have byte pairs");
    compact
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex fixture is utf8");
            u8::from_str_radix(text, 16).expect("hex fixture contains only hex")
        })
        .collect()
}

#[test]
fn dns_packet_corpus_parses_expected_queries() {
    let cases = [
        (
            "dns_a_example_com.hex",
            "10.0.0.10",
            "8.8.8.8",
            "example.com",
            1,
            "A",
        ),
        (
            "dns_aaaa_innerwarden_dev.hex",
            "10.0.0.11",
            "1.1.1.1",
            "innerwarden.dev",
            28,
            "AAAA",
        ),
        (
            "dns_txt_long_subdomain.hex",
            "10.0.0.12",
            "9.9.9.9",
            "alpha.beta.gamma.example.org",
            16,
            "TXT",
        ),
        (
            "dns_mx_mail_example.hex",
            "10.0.0.13",
            "8.8.4.4",
            "mail.example.com",
            15,
            "MX",
        ),
    ];

    for (file, src_ip, dst_ip, domain, qtype, qtype_name) in cases {
        let packet = fixture(file);
        let (actual_src, _src_port, actual_dst, dst_port, payload) =
            dns_capture::parse_packet(&packet).expect("DNS frame should parse");
        let (_tx_id, actual_domain, actual_qtype) =
            dns_capture::parse_dns_query(payload).expect("DNS query should parse");

        assert_eq!(actual_src, src_ip);
        assert_eq!(actual_dst, dst_ip);
        assert_eq!(dst_port, 53);
        assert_eq!(actual_domain, domain);
        assert_eq!(actual_qtype, qtype);
        assert_eq!(dns_capture::qtype_name(actual_qtype), qtype_name);
    }
}

#[test]
fn http_packet_corpus_parses_expected_requests() {
    let cases = [
        (
            "http_get_root.hex",
            "203.0.113.10",
            80,
            "GET",
            "/",
            "example.com",
            "curl/8.0",
        ),
        (
            "http_post_login.hex",
            "203.0.113.11",
            8080,
            "POST",
            "/login",
            "app.local",
            "Mozilla/5.0",
        ),
        (
            "http_get_env_probe.hex",
            "203.0.113.12",
            80,
            "GET",
            "/.env",
            "victim.example",
            "Nikto/2.1.6",
        ),
    ];

    for (file, src_ip, dst_port, method, path, host, user_agent) in cases {
        let packet = fixture(file);
        let (actual_src, _src_port, _dst_ip, actual_dst_port, payload) =
            http_capture::parse_tcp_packet(&packet).expect("HTTP frame should parse");
        let request = http_capture::parse_http_request(payload).expect("HTTP request should parse");

        assert_eq!(actual_src, src_ip);
        assert_eq!(actual_dst_port, dst_port);
        assert_eq!(request.method, method);
        assert_eq!(request.path, path);
        assert_eq!(request.host, host);
        assert_eq!(request.user_agent, user_agent);
    }
}

#[test]
fn tls_packet_corpus_parses_client_hello_fingerprints() {
    let cases = [
        (
            "tls_client_hello_example_h2.hex",
            "198.51.100.20",
            "example.com",
            vec!["h2"],
        ),
        (
            "tls_client_hello_innerwarden_http11.hex",
            "198.51.100.21",
            "api.innerwarden.dev",
            vec!["http/1.1"],
        ),
        (
            "tls_client_hello_no_sni.hex",
            "198.51.100.22",
            "",
            vec!["h2"],
        ),
    ];

    for (file, src_ip, sni, alpn) in cases {
        let packet = fixture(file);
        let hello = tls_fingerprint::parse_packet(&packet).expect("TLS frame should parse");
        let fingerprint = tls_fingerprint::compute_fingerprints(&hello);

        assert_eq!(hello.src_ip, src_ip);
        assert_eq!(hello.dst_port, 443);
        assert_eq!(hello.sni, sni);
        assert_eq!(hello.alpn, alpn);
        assert_eq!(fingerprint.ja3_hash.len(), 32);
        assert!(fingerprint.ja4.starts_with("t12"));
    }
}
