pub const MIN_CHUNK_SIZE: u32 = 1024 * 1024;
pub const AVG_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

pub fn stream_chunker<R: std::io::Read>(reader: R) -> fastcdc::v2020::StreamCDC<R> {
    fastcdc::v2020::StreamCDC::new(reader, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE)
}
