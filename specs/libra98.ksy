meta:
  id: libra98
  title: LIBRA-98 Municipal Library Circulation Database
  file-extension: dat
  endian: le

seq:
  - id: magic
    contents: "LB98"
  - id: version
    type: u2
  - id: declared_count
    type: u2
  - id: dos_date
    type: u2
  - id: dos_time
    type: u2
  - id: data_offset
    type: u2
  - id: branch_id
    type: u2
  - id: records
    type: record
    repeat: eos

types:
  record:
    seq:
      - id: sync
        contents: [0xa5]
      - id: rec_len
        type: u1
      - id: flags
        type: u1
      - id: id
        type: u4
      - id: title_len
        type: u1
      - id: title
        size: title_len
        type: str
        encoding: cp437
      - id: author_len
        type: u1
      - id: author
        size: author_len
        type: str
        encoding: cp437
      - id: year_raw
        type: u2
      - id: price_cents
        type: u2
      - id: copies
        type: u1
      - id: isbn
        size: 10
        type: str
        encoding: ascii
      - id: due_date
        type: u2
        if: (flags & 0x01) != 0
