//! Kill chain pattern definitions — mirrors the kernel eBPF PID_CHAIN bitmask.

// 9 bit flags for syscall categories
pub const CHAIN_SOCKET: u32 = 1 << 0; // connect/socket (outbound)
pub const CHAIN_DUP_STDIN: u32 = 1 << 1; // dup2(fd, 0)
pub const CHAIN_DUP_STDOUT: u32 = 1 << 2; // dup2(fd, 1)
pub const CHAIN_DUP_STDERR: u32 = 1 << 3; // dup2(fd, 2)
pub const CHAIN_BIND: u32 = 1 << 4; // bind
pub const CHAIN_LISTEN: u32 = 1 << 5; // listen
pub const CHAIN_PTRACE: u32 = 1 << 6; // ptrace
pub const CHAIN_MPROTECT: u32 = 1 << 7; // mprotect(RWX)
pub const CHAIN_SENSITIVE_READ: u32 = 1 << 8; // openat on sensitive path

// 8 attack patterns
pub const PATTERN_REVERSE_SHELL: u32 = CHAIN_SOCKET | CHAIN_DUP_STDIN | CHAIN_DUP_STDOUT;
pub const PATTERN_BIND_SHELL: u32 = CHAIN_BIND | CHAIN_LISTEN | CHAIN_DUP_STDIN | CHAIN_DUP_STDOUT;
pub const PATTERN_CODE_INJECT: u32 = CHAIN_PTRACE | CHAIN_MPROTECT;
pub const PATTERN_EXPLOIT_SHELL: u32 = CHAIN_MPROTECT | CHAIN_DUP_STDIN | CHAIN_DUP_STDOUT;
pub const PATTERN_INJECT_SHELL: u32 = CHAIN_PTRACE | CHAIN_DUP_STDIN;
pub const PATTERN_EXPLOIT_C2: u32 = CHAIN_MPROTECT | CHAIN_SOCKET;
pub const PATTERN_FULL_EXPLOIT: u32 = CHAIN_MPROTECT | CHAIN_PTRACE | CHAIN_SOCKET;
pub const PATTERN_DATA_EXFIL: u32 = CHAIN_SENSITIVE_READ | CHAIN_SOCKET;

/// All defined patterns as (name, bitmask) pairs.
pub const ALL_PATTERNS: &[(&str, u32)] = &[
    ("reverse_shell", PATTERN_REVERSE_SHELL),
    ("bind_shell", PATTERN_BIND_SHELL),
    ("code_inject", PATTERN_CODE_INJECT),
    ("exploit_shell", PATTERN_EXPLOIT_SHELL),
    ("inject_shell", PATTERN_INJECT_SHELL),
    ("exploit_c2", PATTERN_EXPLOIT_C2),
    ("full_exploit", PATTERN_FULL_EXPLOIT),
    ("data_exfil", PATTERN_DATA_EXFIL),
];

/// All flag definitions as (name, bit) pairs.
const ALL_FLAGS: &[(&str, u32)] = &[
    ("socket", CHAIN_SOCKET),
    ("dup_stdin", CHAIN_DUP_STDIN),
    ("dup_stdout", CHAIN_DUP_STDOUT),
    ("dup_stderr", CHAIN_DUP_STDERR),
    ("bind", CHAIN_BIND),
    ("listen", CHAIN_LISTEN),
    ("ptrace", CHAIN_PTRACE),
    ("mprotect", CHAIN_MPROTECT),
    ("sensitive_read", CHAIN_SENSITIVE_READ),
];

/// Returns names of ALL patterns whose required bits are fully present in `flags`.
pub fn match_patterns(flags: u32) -> Vec<&'static str> {
    ALL_PATTERNS
        .iter()
        .filter(|(_, pattern)| flags & *pattern == *pattern)
        .map(|(name, _)| *name)
        .collect()
}

/// Returns the pattern with the most bits matched (most specific).
/// Among patterns that fully match, picks the one with the highest popcount.
pub fn best_match(flags: u32) -> Option<&'static str> {
    ALL_PATTERNS
        .iter()
        .filter(|(_, pattern)| flags & *pattern == *pattern)
        .max_by_key(|(_, pattern)| pattern.count_ones())
        .map(|(name, _)| *name)
}

/// Fraction of a pattern's required bits that are present in `flags`.
/// Returns matched_bits / total_bits_in_pattern.
pub fn proximity(flags: u32, pattern: u32) -> f32 {
    let total = pattern.count_ones();
    if total == 0 {
        return 0.0;
    }
    let matched = (flags & pattern).count_ones();
    matched as f32 / total as f32
}

/// Returns the highest proximity across all patterns and the name of that pattern.
pub fn max_proximity(flags: u32) -> (f32, &'static str) {
    ALL_PATTERNS
        .iter()
        .map(|(name, pattern)| (proximity(flags, *pattern), *name))
        .max_by(|(a, _), (b, _)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or((0.0, "unknown"))
}

/// Converts a bitmask to a list of human-readable flag names.
pub fn flag_names(flags: u32) -> Vec<&'static str> {
    ALL_FLAGS
        .iter()
        .filter(|(_, bit)| flags & *bit != 0)
        .map(|(name, _)| *name)
        .collect()
}

/// Returns the flag names required by a given pattern name.
pub fn pattern_flag_names(pattern_name: &str) -> Vec<&'static str> {
    ALL_PATTERNS
        .iter()
        .find(|(name, _)| *name == pattern_name)
        .map(|(_, pattern)| flag_names(*pattern))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Each pattern matches with exact flags ---

    #[test]
    fn test_reverse_shell_exact_match() {
        let flags = PATTERN_REVERSE_SHELL;
        let matches = match_patterns(flags);
        assert!(matches.contains(&"reverse_shell"));
    }

    #[test]
    fn test_bind_shell_exact_match() {
        let flags = PATTERN_BIND_SHELL;
        let matches = match_patterns(flags);
        assert!(matches.contains(&"bind_shell"));
    }

    #[test]
    fn test_code_inject_exact_match() {
        let flags = PATTERN_CODE_INJECT;
        let matches = match_patterns(flags);
        assert!(matches.contains(&"code_inject"));
    }

    #[test]
    fn test_exploit_shell_exact_match() {
        let flags = PATTERN_EXPLOIT_SHELL;
        let matches = match_patterns(flags);
        assert!(matches.contains(&"exploit_shell"));
    }

    #[test]
    fn test_inject_shell_exact_match() {
        let flags = PATTERN_INJECT_SHELL;
        let matches = match_patterns(flags);
        assert!(matches.contains(&"inject_shell"));
    }

    #[test]
    fn test_exploit_c2_exact_match() {
        let flags = PATTERN_EXPLOIT_C2;
        let matches = match_patterns(flags);
        assert!(matches.contains(&"exploit_c2"));
    }

    #[test]
    fn test_full_exploit_exact_match() {
        let flags = PATTERN_FULL_EXPLOIT;
        let matches = match_patterns(flags);
        assert!(matches.contains(&"full_exploit"));
    }

    // --- No false matches with incomplete flags ---

    #[test]
    fn test_no_match_with_single_socket_flag() {
        let flags = CHAIN_SOCKET;
        let matches = match_patterns(flags);
        // socket alone does not complete any pattern
        assert!(matches.is_empty());
    }

    #[test]
    fn test_no_match_with_partial_reverse_shell() {
        // reverse_shell needs socket + dup_stdin + dup_stdout
        let flags = CHAIN_SOCKET | CHAIN_DUP_STDIN; // missing dup_stdout
        let matches = match_patterns(flags);
        assert!(!matches.contains(&"reverse_shell"));
    }

    #[test]
    fn test_no_match_with_partial_bind_shell() {
        // bind_shell needs bind + listen + dup_stdin + dup_stdout
        let flags = CHAIN_BIND | CHAIN_LISTEN; // missing dup_stdin + dup_stdout
        let matches = match_patterns(flags);
        assert!(!matches.contains(&"bind_shell"));
    }

    #[test]
    fn test_no_match_zero_flags() {
        let matches = match_patterns(0);
        assert!(matches.is_empty());
    }

    // --- Proximity calculation ---

    #[test]
    fn test_proximity_zero() {
        // No bits in common
        let prox = proximity(CHAIN_BIND, PATTERN_REVERSE_SHELL);
        assert!((prox - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_proximity_one_third() {
        // reverse_shell needs 3 bits; only socket set
        let prox = proximity(CHAIN_SOCKET, PATTERN_REVERSE_SHELL);
        assert!((prox - 1.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_proximity_two_thirds() {
        // reverse_shell needs 3 bits; socket + dup_stdin set
        let prox = proximity(CHAIN_SOCKET | CHAIN_DUP_STDIN, PATTERN_REVERSE_SHELL);
        assert!((prox - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_proximity_full() {
        let prox = proximity(PATTERN_REVERSE_SHELL, PATTERN_REVERSE_SHELL);
        assert!((prox - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_proximity_superset_is_still_full() {
        // Extra flags beyond the pattern should not reduce proximity
        let flags = PATTERN_REVERSE_SHELL | CHAIN_PTRACE | CHAIN_MPROTECT;
        let prox = proximity(flags, PATTERN_REVERSE_SHELL);
        assert!((prox - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_proximity_empty_pattern() {
        let prox = proximity(CHAIN_SOCKET, 0);
        assert!((prox - 0.0).abs() < f32::EPSILON);
    }

    // --- flag_names ---

    #[test]
    fn test_flag_names_single() {
        let names = flag_names(CHAIN_SOCKET);
        assert_eq!(names, vec!["socket"]);
    }

    #[test]
    fn test_flag_names_multiple() {
        let names = flag_names(CHAIN_SOCKET | CHAIN_DUP_STDIN | CHAIN_MPROTECT);
        assert_eq!(names, vec!["socket", "dup_stdin", "mprotect"]);
    }

    #[test]
    fn test_flag_names_all() {
        let names = flag_names(0xFF);
        assert_eq!(names.len(), 8);
        assert_eq!(
            names,
            vec![
                "socket",
                "dup_stdin",
                "dup_stdout",
                "dup_stderr",
                "bind",
                "listen",
                "ptrace",
                "mprotect",
            ]
        );
    }

    #[test]
    fn test_flag_names_empty() {
        let names = flag_names(0);
        assert!(names.is_empty());
    }

    // --- match_patterns returns multiple when overlapping ---

    #[test]
    fn test_multiple_matches_with_superset_flags() {
        // Set all flags (9 bits): every pattern should match
        let flags = 0x1FF;
        let matches = match_patterns(flags);
        assert_eq!(matches.len(), ALL_PATTERNS.len());
    }

    #[test]
    fn test_overlapping_patterns_code_inject_and_inject_shell() {
        // code_inject = ptrace | mprotect
        // inject_shell = ptrace | dup_stdin
        // Setting ptrace | mprotect | dup_stdin should match both
        let flags = CHAIN_PTRACE | CHAIN_MPROTECT | CHAIN_DUP_STDIN;
        let matches = match_patterns(flags);
        assert!(matches.contains(&"code_inject"));
        assert!(matches.contains(&"inject_shell"));
    }

    #[test]
    fn test_overlapping_exploit_c2_and_reverse_shell() {
        // exploit_c2 = mprotect | socket
        // reverse_shell = socket | dup_stdin | dup_stdout
        let flags = CHAIN_MPROTECT | CHAIN_SOCKET | CHAIN_DUP_STDIN | CHAIN_DUP_STDOUT;
        let matches = match_patterns(flags);
        assert!(matches.contains(&"exploit_c2"));
        assert!(matches.contains(&"reverse_shell"));
    }

    // --- best_match returns most specific ---

    #[test]
    fn test_best_match_picks_most_bits() {
        // bind_shell has 4 bits, reverse_shell has 3 bits
        // Setting all of bind_shell's bits should pick bind_shell
        let flags = PATTERN_BIND_SHELL;
        let best = best_match(flags);
        assert_eq!(best, Some("bind_shell"));
    }

    #[test]
    fn test_best_match_none_when_no_pattern_matches() {
        let best = best_match(CHAIN_BIND); // only bind, no pattern is just bind
        assert_eq!(best, None);
    }

    #[test]
    fn test_best_match_with_all_flags() {
        // With all flags set, bind_shell (4 bits) is the most specific
        let best = best_match(0xFF);
        assert_eq!(best, Some("bind_shell"));
    }

    #[test]
    fn test_best_match_full_exploit_over_code_inject() {
        // full_exploit = mprotect | ptrace | socket (3 bits)
        // code_inject = ptrace | mprotect (2 bits)
        // exploit_c2 = mprotect | socket (2 bits)
        let flags = PATTERN_FULL_EXPLOIT;
        let best = best_match(flags);
        assert_eq!(best, Some("full_exploit"));
    }

    // --- max_proximity ---

    #[test]
    fn test_max_proximity_exact_match() {
        let (prox, name) = max_proximity(PATTERN_REVERSE_SHELL);
        assert!((prox - 1.0).abs() < f32::EPSILON);
        assert_eq!(name, "reverse_shell");
    }

    #[test]
    fn test_max_proximity_partial() {
        // ptrace alone: closest is inject_shell (ptrace | dup_stdin) at 0.5
        // and code_inject (ptrace | mprotect) at 0.5
        let (prox, _name) = max_proximity(CHAIN_PTRACE);
        assert!((prox - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_max_proximity_zero_flags() {
        let (prox, _name) = max_proximity(0);
        assert!((prox - 0.0).abs() < f32::EPSILON);
    }

    // --- pattern_flag_names ---

    #[test]
    fn test_pattern_flag_names_reverse_shell() {
        let names = pattern_flag_names("reverse_shell");
        assert_eq!(names, vec!["socket", "dup_stdin", "dup_stdout"]);
    }

    #[test]
    fn test_pattern_flag_names_bind_shell() {
        let names = pattern_flag_names("bind_shell");
        assert_eq!(names, vec!["dup_stdin", "dup_stdout", "bind", "listen"]);
    }

    #[test]
    fn test_pattern_flag_names_full_exploit() {
        let names = pattern_flag_names("full_exploit");
        assert_eq!(names, vec!["socket", "ptrace", "mprotect"]);
    }

    #[test]
    fn test_pattern_flag_names_unknown_returns_empty() {
        let names = pattern_flag_names("nonexistent");
        assert!(names.is_empty());
    }
}
