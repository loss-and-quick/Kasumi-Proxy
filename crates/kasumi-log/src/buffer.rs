//! The last N records, kept in memory for the window before the log file exists.
//!
//! A daemon that dies during boot leaves nothing on disk: the file sink is opened
//! late, and the shell redirect that normally catches it can be the thing that is
//! missing. The ring buffer is what makes those first seconds readable — and it is
//! process-local, which is fine, because whoever asks is inside the same process.

use std::collections::VecDeque;
use std::sync::Mutex;

struct Tail {
    capacity: usize,
    lines: VecDeque<String>,
}

const UNSET: Tail = Tail {
    capacity: 0,
    lines: VecDeque::new(),
};

static TAIL: Mutex<Tail> = Mutex::new(UNSET);

/// Set how many records to keep. Called once from [`crate::init`]; `0` turns the
/// buffer off and makes [`push`] a no-op.
pub fn configure(capacity: usize) {
    if let Ok(mut tail) = TAIL.lock() {
        tail.capacity = capacity;
        while tail.lines.len() > capacity {
            tail.lines.pop_front();
        }
    }
}

/// Append one already formatted record, dropping the oldest once full.
pub fn push(line: String) {
    if let Ok(mut tail) = TAIL.lock()
        && tail.capacity > 0
    {
        while tail.lines.len() >= tail.capacity {
            tail.lines.pop_front();
        }
        tail.lines.push_back(line);
    }
}

/// Forget the buffered records. The in-app "clear logs" action empties both the
/// files and this, so a cleared viewer does not keep showing records that are no
/// longer readable anywhere.
pub fn clear() {
    if let Ok(mut tail) = TAIL.lock() {
        tail.lines.clear();
    }
}

/// The last `n` records, oldest first.
pub fn recent(n: usize) -> Vec<String> {
    let Ok(tail) = TAIL.lock() else {
        return Vec::new();
    };
    let from = tail.lines.len().saturating_sub(n);
    tail.lines.iter().skip(from).cloned().collect()
}

/// How many records are currently buffered.
pub fn len() -> usize {
    TAIL.lock().map(|tail| tail.lines.len()).unwrap_or(0)
}

/// Whether nothing is buffered (also true when buffering is disabled).
pub fn is_empty() -> bool {
    len() == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The buffer is process-global by design, so its tests share one lock and run
    /// in sequence — parallel tests would reconfigure each other's capacity.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn keeps_recent_in_order() {
        let _guard = exclusive();
        configure(4);
        for i in 0..4 {
            push(format!("line {i}"));
        }
        assert_eq!(recent(2), ["line 2", "line 3"]);
        assert_eq!(len(), 4);
    }

    #[test]
    fn drops_the_oldest_when_full() {
        let _guard = exclusive();
        configure(3);
        for i in 0..10 {
            push(format!("line {i}"));
        }
        assert_eq!(recent(usize::MAX), ["line 7", "line 8", "line 9"]);
    }

    #[test]
    fn zero_capacity_disables_buffering() {
        let _guard = exclusive();
        configure(0);
        push("dropped".into());
        assert!(is_empty());
        assert!(recent(5).is_empty());
    }

    #[test]
    fn recent_beyond_capacity_returns_everything() {
        let _guard = exclusive();
        configure(8);
        clear();
        push("a".into());
        push("b".into());
        assert_eq!(recent(100), ["a", "b"]);
    }
}
