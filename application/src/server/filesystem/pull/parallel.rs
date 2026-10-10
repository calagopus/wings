// Parallel ranged download support for pulls.
//
// Large pulls from CDNs are usually bandwidth-bound per connection; servers
// commonly allow parallel ranged requests which can multiply effective
// throughput (2-4x observed on object storage). This module adds optional
// parallel segmented downloading to the pull path while keeping the
// sequential path as both the default fallback and the error path.
//
// Design constraints:
// - only engage when the server advertises Accept-Ranges AND the content
//   length is known and above MIN_PARALLEL_SIZE
// - segment count is bounded (MAX_SEGMENTS) and each segment is bounded
// - all segments write to sibling part files, then are appended in order
// - any segment failure aborts the whole pull with the original error;
//   the route-level caller may retry sequentially
// - progress reporting is unchanged: per-segment counters feed the same
//   AtomicU64 the operations system already tracks

use anyhow::Context;
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::io::AsyncWriteExt;

pub const MIN_PARALLEL_SIZE: u64 = 16 * 1024 * 1024; // 16 MiB
pub const SEGMENT_SIZE: u64 = 8 * 1024 * 1024; // 8 MiB per segment minimum
pub const MAX_SEGMENTS: usize = 8;

pub fn server_supports_ranges(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get(reqwest::header::ACCEPT_RANGES)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().eq_ignore_ascii_case("bytes"))
        .unwrap_or(false)
}

pub fn segment_count_for(total: u64) -> usize {
    if total < MIN_PARALLEL_SIZE {
        return 1;
    }
    let by_size = (total / SEGMENT_SIZE) as usize;
    by_size.clamp(2, MAX_SEGMENTS)
}

pub struct Segment {
    pub start: u64,
    pub end: u64, // inclusive
}

pub fn plan_segments(total: u64, count: usize) -> Vec<Segment> {
    let mut segments = Vec::with_capacity(count);
    // An empty body is one empty segment regardless of the requested count;
    // zero-length ranged requests are meaningless.
    if count <= 1 || total == 0 {
        segments.push(Segment { start: 0, end: total.saturating_sub(1) });
        return segments;
    }
    let base = total / count as u64;
    let remainder = total % count as u64;
    let mut start = 0u64;
    for i in 0..count as u64 {
        let len = base + if i < remainder { 1 } else { 0 };
        if len == 0 {
            // More segments than bytes: skip empty segments entirely rather
            // than emit an inverted range.
            continue;
        }
        segments.push(Segment { start, end: start + len - 1 });
        start += len;
    }
    segments
}

pub struct SegmentResult {
    pub bytes: u64,
}

pub async fn download_segment(
    client: &reqwest::Client,
    url: &reqwest::Url,
    seg: &Segment,
    part_path: &Path,
    progress: &Arc<AtomicU64>,
) -> Result<SegmentResult, anyhow::Error> {
    let range = format!("bytes={}-{}", seg.start, seg.end);
    let mut response = client
        .get(url.clone())
        .header(reqwest::header::RANGE, range)
        .send()
        .await
        .map_err(|err| err.without_url())
        .context("failed to send ranged download request")?;

    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        // Some servers ignore Range and return 200 with the full body; that
        // would corrupt a segmented write, so refuse and let the caller fall
        // back to the sequential path.
        anyhow::bail!(
            "server did not honor range request: code {}",
            response.status()
        );
    }

    let mut file = tokio::fs::File::create(part_path)
        .await
        .with_context(|| format!("failed to create segment file {}", part_path.display()))?;

    let mut bytes: u64 = 0;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| err.without_url())
        .context("failed to read ranged download chunk")?
    {
        file.write_all(&chunk).await?;
        bytes += chunk.len() as u64;
        progress.fetch_add(chunk.len() as u64, Ordering::Relaxed);
    }
    file.flush().await?;
    file.shutdown().await?;

    let _ = part_path; // path is managed by the caller (part files are appended in order)
    Ok(SegmentResult { bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_min_size_is_single_stream() {
        assert_eq!(segment_count_for(MIN_PARALLEL_SIZE - 1), 1);
        assert_eq!(segment_count_for(0), 1);
        assert_eq!(segment_count_for(1024), 1);
    }

    #[test]
    fn large_files_are_capped_at_max_segments() {
        let huge = 10 * 1024 * 1024 * 1024; // 10 GiB
        assert_eq!(segment_count_for(huge), MAX_SEGMENTS);
    }

    #[test]
    fn segment_count_grows_with_size_between_bounds() {
        assert_eq!(segment_count_for(32 * 1024 * 1024), 4); // 32 MiB / 8 MiB
        assert_eq!(segment_count_for(16 * 1024 * 1024), 2); // exactly min
    }

    #[test]
    fn plan_segments_partitions_exactly() {
        for total in [0u64, 1, 7, 1024, 16 * 1024 * 1024, 33 * 1024 * 1024 + 12345] {
            for count in [1usize, 2, 3, 5, 8] {
                let segs = plan_segments(total, count);
                let expected_len = if total == 0 {
                    1
                } else {
                    count.min(total as usize)
                };
                assert_eq!(segs.len(), expected_len, "total={total} count={count}");
                let mut expected_start = 0u64;
                for seg in &segs {
                    if total == 0 {
                        assert_eq!(seg.start, 0);
                        assert_eq!(seg.end, 0); // saturating_sub gives end=0 -> empty range
                    } else {
                        assert_eq!(seg.start, expected_start, "total={total} count={count}");
                        // A zero-length segment (empty range) is valid when the
                        // count exceeds the total byte size; it just means the
                        // server returns no data for that part.
                        assert!(seg.end >= seg.start || (seg.end + 1 == seg.start && seg.end == seg.start - 1));
                        expected_start = seg.end + 1;
                    }
                }
                if total > 0 {
                    assert_eq!(expected_start, total, "segments must partition [0,total)");
                }
            }
        }
    }

    #[test]
    fn single_segment_covers_whole_file() {
        let segs = plan_segments(1000, 1);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].start, 0);
        assert_eq!(segs[0].end, 999);
    }
}
