meta:
  id: lablog
  title: LABLOG Analytical Instrument Telemetry Logger Stream
  file-extension: dat
  endian: le

seq:
  - id: magic
    contents: "LLOG"
  - id: version
    type: u1
  - id: num_channels
    type: u1
  - id: interval_raw
    type: u2
  - id: instrument
    size: 16
    type: str
    encoding: ascii
  - id: start_ts
    type: u4
  - id: declared_blocks
    type: u2
  - id: hdr_crc
    type: u2
  - id: blocks
    type: block
    repeat: eos

types:
  block:
    seq:
      - id: sync
        contents: [0xb1]
      - id: block_type
        type: u1
      - id: block_len
        type: u2
      - id: payload
        size: block_len
      - id: stored_crc
        type: u2
