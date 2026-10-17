meta:
  id: wks
  title: Lotus 1-2-3 DOS Spreadsheet (.WKS)
  file-extension: wks
  endian: le

seq:
  - id: records
    type: record
    repeat: eos

types:
  record:
    seq:
      - id: opcode
        type: u2
      - id: length
        type: u2
      - id: body
        size: length
