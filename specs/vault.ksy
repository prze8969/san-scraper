meta:
  id: vault
  title: VAULT School Office Container Archive
  file-extension: dat
  endian: le

seq:
  - id: magic
    contents: "VLT1"
  - id: entry_count
    type: u2
  - id: xor_key
    type: u1
  - id: flags
    type: u1
  - id: flags_extended
    type: u4
  - id: index_offset
    type: u4

types:
  entry_descriptor:
    seq:
      - id: id
        type: u2
      - id: type_code
        type: u2
      - id: payload_offset
        type: u4
      - id: payload_size
        type: u4
      - id: compressed_flag
        type: u2
      - id: reserved
        type: u2
