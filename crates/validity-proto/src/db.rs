//! The on-chip record database: user storage, users, enrolled fingers
//! (python-validity `db.py`, `init_db.py`).
//!
//! Records form a tree: the storage `StgWindsor` holds users (type 5), users hold
//! fingers (type 6, created as 0xb), fingers may hold data records (type 8).

use crate::cmd::{Error, Reader, checked, status, status_word};
use crate::flash::{with_cleanups, write_enable};
use crate::session::Sensor;
use crate::sid::Sid;
use crate::tables::finger_name;
use crate::vendor::Blobs;

/// Name of the user storage created by the Windows driver.
pub const STORAGE_NAME: &str = "StgWindsor";
/// Status: no such record.
pub const STATUS_NOT_FOUND: u16 = 0x04b3;

pub const TYPE_STORAGE: u16 = 4;
pub const TYPE_USER: u16 = 5;
/// Requested type of a new finger; the sensor stores it as type 6.
pub const TYPE_FINGER_NEW: u16 = 0xb;
pub const TYPE_DATA: u16 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserRef {
    pub dbid: u16,
    pub value_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserStorage {
    pub dbid: u16,
    /// As stored, including the terminating NUL.
    pub name: Vec<u8>,
    pub users: Vec<UserRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerRef {
    pub dbid: u16,
    pub subtype: u16,
    pub storage: u16,
    pub value_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub dbid: u16,
    pub identity: Sid,
    pub fingers: Vec<FingerRef>,
}

/// `get_user_storage` request: by record id, or by name when `name` is non-empty.
pub fn user_storage_cmd(dbid: u16, name: &str) -> Vec<u8> {
    let mut n = name.as_bytes().to_vec();
    if !n.is_empty() {
        n.push(0);
    }
    let mut c = vec![0x4b];
    c.extend_from_slice(&dbid.to_le_bytes());
    c.extend_from_slice(&(n.len() as u16).to_le_bytes());
    c.extend(n);
    c
}

/// `None` when the storage does not exist.
pub fn parse_user_storage(rsp: &[u8]) -> Result<Option<UserStorage>, Error> {
    if status_word(rsp)? == STATUS_NOT_FOUND {
        return Ok(None);
    }
    let mut r = Reader::new(status(rsp)?, "user storage");
    let (dbid, count, name_len, _unknown) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
    let users = (0..count)
        .map(|_| {
            Ok(UserRef {
                dbid: r.u16()?,
                value_size: r.u16()?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let name = r.bytes(name_len as usize)?.to_vec();
    r.end()?;
    Ok(Some(UserStorage { dbid, name, users }))
}

/// Identity record value: `type 3 (le32) || len (le32) || SID`, zero-padded to the
/// 0x4c bytes of the Windows union (lookups compare the padded value).
pub fn identity_to_bytes(sid: &Sid) -> Vec<u8> {
    let s = sid.to_bytes();
    let mut b = 3u32.to_le_bytes().to_vec();
    b.extend_from_slice(&(s.len() as u32).to_le_bytes());
    b.extend(s);
    if b.len() < 0x4c {
        b.resize(0x4c, 0);
    }
    b
}

pub fn parse_identity(b: &[u8]) -> Result<Sid, Error> {
    let mut r = Reader::new(b, "identity");
    let t = r.u32()?;
    if t != 3 {
        return Err(Error::Protocol(format!("unknown identity type {t}")));
    }
    let len = r.u32()? as usize;
    Sid::from_bytes(r.bytes(len)?)
}

pub fn parse_user(rsp: &[u8]) -> Result<User, Error> {
    let mut r = Reader::new(status(rsp)?, "user");
    let (dbid, count, _unknown, identity_len) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
    let fingers = (0..count)
        .map(|_| {
            Ok(FingerRef {
                dbid: r.u16()?,
                subtype: r.u16()?,
                storage: r.u16()?,
                value_size: r.u16()?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let identity = parse_identity(r.bytes(identity_len as usize)?)?;
    r.end()?;
    Ok(User {
        dbid,
        identity,
        fingers,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub dbid: u16,
    pub kind: u16,
    pub storage: u16,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildRef {
    pub dbid: u16,
    pub kind: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Children {
    pub dbid: u16,
    pub kind: u16,
    pub storage: u16,
    pub value_size: u16,
    pub children: Vec<ChildRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbInfo {
    pub unknown1: u32,
    pub unknown0: u32,
    /// Partition size.
    pub total: u32,
    /// Used by live records.
    pub used: u32,
    /// Unallocated.
    pub free: u32,
    /// Including deleted records.
    pub records: u16,
    pub roots: Vec<u16>,
}

pub fn parse_record_value(rsp: &[u8]) -> Result<Record, Error> {
    let mut r = Reader::new(status(rsp)?, "record value");
    let (dbid, kind, storage, size) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
    r.skip(2)?;
    Ok(Record {
        dbid,
        kind,
        storage,
        value: r.bytes(size as usize)?.to_vec(),
    })
}

pub fn parse_record_children(rsp: &[u8]) -> Result<Children, Error> {
    let mut r = Reader::new(status(rsp)?, "record children");
    let (dbid, kind, storage, value_size, count) =
        (r.u16()?, r.u16()?, r.u16()?, r.u16()?, r.u16()?);
    r.skip(2)?;
    let children = (0..count)
        .map(|_| {
            Ok(ChildRef {
                dbid: r.u16()?,
                kind: r.u16()?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(Children {
        dbid,
        kind,
        storage,
        value_size,
        children,
    })
}

pub fn parse_db_info(rsp: &[u8]) -> Result<DbInfo, Error> {
    let mut r = Reader::new(status(rsp)?, "db info");
    let (unknown1, unknown0, total, used, free) =
        (r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?);
    let (records, nroots) = (r.u16()?, r.u16()?);
    let roots = (0..nroots).map(|_| r.u16()).collect::<Result<_, _>>()?;
    Ok(DbInfo {
        unknown1,
        unknown0,
        total,
        used,
        free,
        records,
        roots,
    })
}

/// `0x47 parent type storage len data`.
pub fn new_record_cmd(parent: u16, kind: u16, storage: u16, data: &[u8]) -> Vec<u8> {
    let mut c = vec![0x47];
    for v in [parent, kind, storage, data.len() as u16] {
        c.extend_from_slice(&v.to_le_bytes());
    }
    c.extend_from_slice(data);
    c
}

/// Finger record value: `subtype, 3, len, 0x20` header, template (tag 1) and
/// template id (tag 2) as tagged values, then 0x20 zero bytes.
pub fn make_finger_data(subtype: u16, template: &[u8], tid: &[u8]) -> Vec<u8> {
    let mut tinfo = Vec::new();
    for (tag, v) in [(1u16, template), (2, tid)] {
        tinfo.extend_from_slice(&tag.to_le_bytes());
        tinfo.extend_from_slice(&(v.len() as u16).to_le_bytes());
        tinfo.extend_from_slice(v);
    }
    let mut out = Vec::with_capacity(8 + tinfo.len() + 0x20);
    for v in [subtype, 3, tinfo.len() as u16, 0x20] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend(tinfo);
    out.extend_from_slice(&[0; 0x20]);
    out
}

pub fn get_user_storage(
    s: &mut impl Sensor,
    dbid: u16,
    name: &str,
) -> Result<Option<UserStorage>, Error> {
    parse_user_storage(&s.cmd(&user_storage_cmd(dbid, name))?)
}

fn storage(s: &mut impl Sensor) -> Result<UserStorage, Error> {
    get_user_storage(s, 0, STORAGE_NAME)?
        .ok_or_else(|| Error::Protocol(format!("no {STORAGE_NAME} user storage")))
}

pub fn get_user(s: &mut impl Sensor, dbid: u16) -> Result<User, Error> {
    let mut c = vec![0x4a];
    for v in [dbid, 0, 0] {
        c.extend_from_slice(&v.to_le_bytes());
    }
    parse_user(&s.cmd(&c)?)
}

/// The user with this identity, if enrolled.
pub fn lookup_user(s: &mut impl Sensor, identity: &Sid) -> Result<Option<User>, Error> {
    let stg = storage(s)?;
    let data = identity_to_bytes(identity);
    let mut c = vec![0x4a];
    for v in [0, stg.dbid, data.len() as u16] {
        c.extend_from_slice(&v.to_le_bytes());
    }
    c.extend(data);
    let rsp = s.cmd(&c)?;
    if status_word(&rsp)? == STATUS_NOT_FOUND {
        return Ok(None);
    }
    parse_user(&rsp).map(Some)
}

pub fn get_record_value(s: &mut impl Sensor, dbid: u16) -> Result<Record, Error> {
    let mut c = vec![0x49];
    c.extend_from_slice(&dbid.to_le_bytes());
    parse_record_value(&s.cmd(&c)?)
}

pub fn get_record_children(s: &mut impl Sensor, dbid: u16) -> Result<Children, Error> {
    let mut c = vec![0x46];
    c.extend_from_slice(&dbid.to_le_bytes());
    parse_record_children(&s.cmd(&c)?)
}

/// Deletes a record and its children. Like the reference, without write enable
/// (not exercised by the recorded sessions).
pub fn del_record(s: &mut impl Sensor, dbid: u16) -> Result<(), Error> {
    let mut c = vec![0x48];
    c.extend_from_slice(&dbid.to_le_bytes());
    checked(s, &c).map(|_| ())
}

pub fn db_info(s: &mut impl Sensor) -> Result<DbInfo, Error> {
    parse_db_info(&s.cmd(&[0x45])?)
}

/// Creates a record; returns its id. Queries the database info first, as the
/// reference does (it intends to check free space there).
pub fn new_record(
    s: &mut impl Sensor,
    blobs: &Blobs,
    parent: u16,
    kind: u16,
    storage: u16,
    data: &[u8],
) -> Result<u16, Error> {
    db_info(s)?;
    write_enable(s, blobs)?;
    with_cleanups(s, |cmd| {
        let rsp = cmd(&new_record_cmd(parent, kind, storage, data))?;
        let mut r = Reader::new(status(&rsp)?, "new record id");
        let id = r.u16()?;
        r.end()?;
        Ok(id)
    })
}

pub fn new_user_storage(s: &mut impl Sensor, blobs: &Blobs) -> Result<u16, Error> {
    let mut name = STORAGE_NAME.as_bytes().to_vec();
    name.push(0);
    new_record(s, blobs, 1, TYPE_STORAGE, 3, &name)
}

pub fn new_user(s: &mut impl Sensor, blobs: &Blobs, identity: &Sid) -> Result<u16, Error> {
    let data = identity_to_bytes(identity);
    let stg = storage(s)?;
    new_record(s, blobs, stg.dbid, TYPE_USER, stg.dbid, &data)
}

/// The write-enable blob makes the sensor store the requested type 0xb as 6.
pub fn new_finger(
    s: &mut impl Sensor,
    blobs: &Blobs,
    user: u16,
    finger_data: &[u8],
) -> Result<u16, Error> {
    let stg = storage(s)?;
    new_record(s, blobs, user, TYPE_FINGER_NEW, stg.dbid, finger_data)
}

pub fn new_data(
    s: &mut impl Sensor,
    blobs: &Blobs,
    parent: u16,
    data: &[u8],
) -> Result<u16, Error> {
    let stg = storage(s)?;
    let mut v = 1u16.to_le_bytes().to_vec();
    v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    v.extend_from_slice(data);
    new_record(s, blobs, parent, TYPE_DATA, stg.dbid, &v)
}

/// Ids of the data records under the storage.
pub fn get_storage_data(s: &mut impl Sensor) -> Result<Vec<u16>, Error> {
    let stg = storage(s)?;
    Ok(get_record_children(s, stg.dbid)?
        .children
        .into_iter()
        .filter(|c| c.kind == TYPE_DATA)
        .map(|c| c.dbid)
        .collect())
}

/// Creates the user storage if missing (`init_db`).
pub fn init_db(s: &mut impl Sensor, blobs: &Blobs) -> Result<(), Error> {
    if get_user_storage(s, 0, STORAGE_NAME)?.is_none() {
        log::info!("creating a new user storage object");
        new_user_storage(s, blobs)?;
    }
    Ok(())
}

/// Every user of the storage with their fingers (`dump_all`).
pub fn list_users(s: &mut impl Sensor) -> Result<Vec<User>, Error> {
    let stg = storage(s)?;
    stg.users.iter().map(|u| get_user(s, u.dbid)).collect()
}

/// The `dump_all` listing.
pub fn format_users(users: &[User]) -> String {
    use core::fmt::Write;
    let mut out = String::new();
    for u in users {
        writeln!(
            out,
            "{:2}: User {} with {} fingers:",
            u.dbid,
            u.identity,
            u.fingers.len()
        )
        .expect("write to String");
        for f in &u.fingers {
            writeln!(
                out,
                "    {:2}: {:02x} ({})",
                f.dbid,
                f.subtype,
                finger_name(f.subtype).unwrap_or("Unknown")
            )
            .expect("write to String");
        }
    }
    out
}

/// A record tree node (`dump_raw`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub record: Record,
    pub children: Vec<Node>,
}

pub fn dump_tree(s: &mut impl Sensor, root: u16) -> Result<Node, Error> {
    let record = get_record_value(s, root)?;
    let children = get_record_children(s, root)?
        .children
        .iter()
        .map(|c| dump_tree(s, c.dbid))
        .collect::<Result<_, _>>()?;
    Ok(Node { record, children })
}

/// Data records of the finger of `user` with `subtype` (`get_finger_blobs`).
pub fn get_finger_blobs(
    s: &mut impl Sensor,
    user: u16,
    subtype: u16,
) -> Result<Vec<Vec<u8>>, Error> {
    let u = get_user(s, user)?;
    let ids: Vec<u16> = u
        .fingers
        .iter()
        .filter(|f| f.subtype == subtype)
        .map(|f| f.dbid)
        .collect();
    let [finger] = ids[..] else {
        return Err(Error::Protocol(format!(
            "expected one finger {subtype} for user {user}, found {}",
            ids.len()
        )));
    };
    get_record_children(s, finger)?
        .children
        .iter()
        .filter(|c| c.kind == TYPE_DATA)
        .map(|c| Ok(get_record_value(s, c.dbid)?.value))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Script, blobs};

    fn sid() -> Sid {
        "S-1-5-21-1-2-3-1000".parse().unwrap()
    }

    fn storage_reply(users: &[(u16, u16)]) -> Vec<u8> {
        let mut r = vec![0, 0, 3, 0];
        r.extend_from_slice(&(users.len() as u16).to_le_bytes());
        r.extend_from_slice(&[11, 0, 0, 0]);
        for (a, b) in users {
            r.extend_from_slice(&a.to_le_bytes());
            r.extend_from_slice(&b.to_le_bytes());
        }
        r.extend_from_slice(b"StgWindsor\0");
        r
    }

    fn user_reply(dbid: u16, fingers: &[(u16, u16)]) -> Vec<u8> {
        let id = identity_to_bytes(&sid());
        let mut r = vec![0, 0];
        for v in [dbid, fingers.len() as u16, 0, id.len() as u16] {
            r.extend_from_slice(&v.to_le_bytes());
        }
        for (f, st) in fingers {
            for v in [*f, *st, 3, 0x0123] {
                r.extend_from_slice(&v.to_le_bytes());
            }
        }
        r.extend(id);
        r
    }

    #[test]
    fn serializers() {
        assert_eq!(
            user_storage_cmd(0, "StgWindsor"),
            b"\x4b\0\0\x0b\0StgWindsor\0"
        );
        assert_eq!(user_storage_cmd(3, ""), [0x4b, 3, 0, 0, 0]);
        let id = identity_to_bytes(&sid());
        assert_eq!(id.len(), 0x4c);
        assert_eq!(&id[..8], [3, 0, 0, 0, 28, 0, 0, 0]);
        assert_eq!(parse_identity(&id).unwrap(), sid());
        assert!(parse_identity(&[4, 0, 0, 0, 0, 0, 0, 0]).is_err());
        // Long SIDs are not truncated or padded.
        let long: Sid = format!("S-1-5{}", "-7".repeat(20)).parse().unwrap();
        assert_eq!(identity_to_bytes(&long).len(), 8 + 8 + 80);
        assert_eq!(
            new_record_cmd(1, 4, 3, b"ab"),
            [0x47, 1, 0, 4, 0, 3, 0, 2, 0, b'a', b'b']
        );
        let f = make_finger_data(7, &[1, 2, 3], &[9]);
        assert_eq!(
            f,
            [
                7, 0, 3, 0, 12, 0, 0x20, 0, 1, 0, 3, 0, 1, 2, 3, 2, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn parsers() {
        let st = parse_user_storage(&storage_reply(&[(0x11, 0x4c)]))
            .unwrap()
            .unwrap();
        assert_eq!(st.dbid, 3);
        assert_eq!(st.name, b"StgWindsor\0");
        assert_eq!(
            st.users,
            [UserRef {
                dbid: 0x11,
                value_size: 0x4c
            }]
        );
        assert_eq!(parse_user_storage(&[0xb3, 0x04]).unwrap(), None);
        let mut junk = storage_reply(&[]);
        junk.push(0);
        assert!(parse_user_storage(&junk).is_err());

        let u = parse_user(&user_reply(0x11, &[(0x21, 1), (0x22, 6)])).unwrap();
        assert_eq!(u.dbid, 0x11);
        assert_eq!(u.identity, sid());
        assert_eq!(u.fingers[1].subtype, 6);
        assert_eq!(
            format_users(&[u]),
            "17: User S-1-5-21-1-2-3-1000 with 2 fingers:\n    33: 01 (right-thumb)\n    34: 06 (left-thumb)\n"
        );

        let rec =
            parse_record_value(&[0, 0, 9, 0, 8, 0, 3, 0, 2, 0, 0, 0, 0xaa, 0xbb, 0xcc]).unwrap();
        assert_eq!((rec.dbid, rec.kind, rec.storage), (9, 8, 3));
        assert_eq!(rec.value, [0xaa, 0xbb]);
        assert!(parse_record_value(&[0, 0, 9, 0, 8, 0, 3, 0, 5, 0, 0, 0, 1]).is_err());

        let ch = parse_record_children(&[
            0, 0, 3, 0, 4, 0, 3, 0, 11, 0, 2, 0, 0, 0, 4, 0, 5, 0, 7, 0, 8, 0,
        ])
        .unwrap();
        assert_eq!(
            ch.children,
            [ChildRef { dbid: 4, kind: 5 }, ChildRef { dbid: 7, kind: 8 }]
        );

        let mut info = vec![0, 0];
        for v in [1u32, 0, 0x80000, 0x40, 0x300] {
            info.extend_from_slice(&v.to_le_bytes());
        }
        info.extend_from_slice(&[3, 0, 1, 0, 3, 0]);
        let i = parse_db_info(&info).unwrap();
        assert_eq!(
            (i.total, i.used, i.free, i.records),
            (0x80000, 0x40, 0x300, 3)
        );
        assert_eq!(i.roots, [3]);
    }

    #[test]
    fn enroll_records_sequence() {
        let b = blobs();
        let stg = storage_reply(&[]);
        let info = {
            let mut r = vec![0, 0];
            r.extend_from_slice(&[0; 20]);
            r.extend_from_slice(&[0, 0, 0, 0]);
            r
        };
        let id = identity_to_bytes(&sid());
        let mut lookup = vec![0x4a, 0, 0, 3, 0, 0x4c, 0];
        lookup.extend(&id);
        let mut s = Script::new(vec![
            (user_storage_cmd(0, STORAGE_NAME), stg.clone()),
            (lookup, vec![0xb3, 0x04]),
            (user_storage_cmd(0, STORAGE_NAME), stg.clone()),
            (vec![0x45], info.clone()),
            (b.db_write_enable.clone(), vec![0, 0]),
            (new_record_cmd(3, TYPE_USER, 3, &id), vec![0, 0, 0x11, 0]),
            (vec![0x1a], vec![0, 0]),
            (user_storage_cmd(0, STORAGE_NAME), stg.clone()),
            (vec![0x45], info.clone()),
            (b.db_write_enable.clone(), vec![0, 0]),
            (
                new_record_cmd(0x11, TYPE_FINGER_NEW, 3, b"tpl"),
                vec![0x01, 0x04],
            ),
            (vec![0x1a], vec![0, 0]),
        ]);
        assert_eq!(lookup_user(&mut s, &sid()).unwrap(), None);
        assert_eq!(new_user(&mut s, &b, &sid()).unwrap(), 0x11);
        assert!(matches!(
            new_finger(&mut s, &b, 0x11, b"tpl"),
            Err(Error::Status(0x0401))
        ));
        s.done();

        let mut s = Script::new(vec![(user_storage_cmd(0, STORAGE_NAME), vec![0xb3, 0x04])]);
        assert!(matches!(
            lookup_user(&mut s, &sid()),
            Err(Error::Protocol(_))
        ));
    }
}
