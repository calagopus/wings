pub const HEADER_SIZE: u64 = 16;
pub const GOODBYE_ITEM_SIZE: u64 = 24;
pub const STAT_SIZE: u64 = 40;

pub const PXAR_FORMAT_VERSION: u64 = 0x730f6c75df16a40d;
pub const PXAR_ENTRY: u64 = 0xd5956474e588acef;
pub const PXAR_FILENAME: u64 = 0x16701121063917b3;
pub const PXAR_SYMLINK: u64 = 0x27f971e7dbf5dc5f;
pub const PXAR_PAYLOAD: u64 = 0x28147a1b0b7c1a25;
pub const PXAR_GOODBYE: u64 = 0x2fec4fa642d5731d;
pub const PXAR_GOODBYE_TAIL_MARKER: u64 = 0xef5eed5b753e1555;

const PXAR_HASH_KEY_1: u64 = 0x83ac3f1cfbb450db;
const PXAR_HASH_KEY_2: u64 = 0xaa4f1b6879369fbd;

#[rustfmt::skip]
pub mod mode {
    pub const IFMT:  u64 = 0o0170000;
    pub const IFLNK: u64 = 0o0120000;
    pub const IFREG: u64 = 0o0100000;
    pub const IFDIR: u64 = 0o0040000;
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub htype: u64,
    pub full_size: u64,
}

impl Header {
    pub fn content_size(self) -> std::io::Result<u64> {
        self.full_size
            .checked_sub(HEADER_SIZE)
            .ok_or_else(|| std::io::Error::other("pxar item header smaller than the header itself"))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GoodbyeItem {
    pub hash: u64,
    pub offset: u64,
    pub size: u64,
}

impl GoodbyeItem {
    pub fn to_le_bytes(self) -> [u8; 24] {
        let mut out = [0; 24];
        if let Some(slot) = out.get_mut(0..8) {
            slot.copy_from_slice(&self.hash.to_le_bytes());
        }
        if let Some(slot) = out.get_mut(8..16) {
            slot.copy_from_slice(&self.offset.to_le_bytes());
        }
        if let Some(slot) = out.get_mut(16..24) {
            slot.copy_from_slice(&self.size.to_le_bytes());
        }

        out
    }

    pub fn from_le_bytes(buf: &[u8]) -> std::io::Result<Self> {
        Ok(Self {
            hash: read_u64(buf.get(0..8))?,
            offset: read_u64(buf.get(8..16))?,
            size: read_u64(buf.get(16..24))?,
        })
    }
}

fn read_u64(bytes: Option<&[u8]>) -> std::io::Result<u64> {
    let array: [u8; 8] = bytes
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| std::io::Error::other("pxar: truncated u64 field"))?;
    Ok(u64::from_le_bytes(array))
}

pub fn hash_filename(name: &[u8]) -> u64 {
    use std::hash::Hasher;

    let mut hasher = siphasher::sip::SipHasher24::new_with_keys(PXAR_HASH_KEY_1, PXAR_HASH_KEY_2);
    hasher.write(name);
    hasher.finish()
}

pub fn validate_filename(name: &[u8]) -> std::io::Result<()> {
    if name.is_empty() {
        return Err(std::io::Error::other("pxar: empty file name"));
    }
    if name.contains(&b'/') {
        return Err(std::io::Error::other("pxar: file name contains a slash"));
    }
    if name == b"." || name == b".." {
        return Err(std::io::Error::other("pxar: file name is '.' or '..'"));
    }

    Ok(())
}

pub fn bst_copy<F: FnMut(usize, usize)>(n: usize, mut copy: F) {
    if n == 0 {
        return;
    }
    let e = (usize::BITS - n.leading_zeros() - 1) as usize;
    bst_copy_inner(&mut copy, n, 0, e, 0);
}

fn bst_copy_inner<F: FnMut(usize, usize)>(copy: &mut F, n: usize, o: usize, e: usize, i: usize) {
    let p = 1usize << e;
    let t = p + (p >> 1) - 1;
    let m = if n > t { p - 1 } else { p - 1 - (t - n) };

    copy(o + m, i);

    if m > 0 {
        bst_copy_inner(copy, m, o, e - 1, i * 2 + 1);
    }
    if (m + 1) < n {
        bst_copy_inner(copy, n - m - 1, o + m + 1, e - 1, i * 2 + 2);
    }
}

pub fn bst_search_by<T, F>(tree: &[T], start: usize, skip: usize, compare: F) -> Option<usize>
where
    F: Copy + Fn(&T) -> std::cmp::Ordering,
{
    use std::cmp::Ordering;

    let mut i = start;
    while let Some(item) = tree.get(i) {
        match compare(item) {
            Ordering::Less => i = 2 * i + 1,
            Ordering::Greater => i = 2 * i + 2,
            Ordering::Equal if skip == 0 => return Some(i),
            Ordering::Equal => {
                let left = 2 * i + 1;
                return bst_search_by(tree, left, skip - 1, compare)
                    .or_else(|| bst_search_by(tree, left + 1, skip - 1, compare));
            }
        }
    }
    None
}
