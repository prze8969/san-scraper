meta:
  id: wad_pak
  title: Doom WAD and Quake PAK Game Archives
  endian: le

types:
  wad_header:
    seq:
      - id: magic
        size: 4
        type: str
        encoding: ascii
      - id: num_lumps
        type: u4
      - id: infotable_offset
        type: u4

  pak_header:
    seq:
      - id: magic
        contents: "PACK"
      - id: dir_offset
        type: u4
      - id: dir_len
        type: u4
