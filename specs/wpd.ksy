meta:
  id: wpd
  title: WordPerfect Document File Format
  file-extension: wpd
  endian: le

seq:
  - id: magic
    contents: [0xff, "WPC"]
  - id: doc_ptr
    type: u4
  - id: product_type
    type: u1
  - id: file_type
    type: u1
  - id: major_version
    type: u1
  - id: minor_version
    type: u1
  - id: enc_key
    type: u2
  - id: reserved
    size: 2
