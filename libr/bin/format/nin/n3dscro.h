#ifndef NIN_N3DS_CRO_H
#define NIN_N3DS_CRO_H

#include <r_types_base.h>

struct n3ds_cro_hdr
{
	ut8 sha256table[4][0x20];
	ut8 magic[4];
	ut32 name_offset;
	ut32 next_cro;
	ut32 previous_cro;
	ut32 size;
	ut32 bss_size;
	ut32 unk98;
	ut32 unk9c;
	ut32 nnroco_offset;
	ut32 onload_offset;
	ut32 onexit_offset;
	ut32 onunresolved_offset;
	ut32 code_offset;
	ut32 code_size;
	ut32 data_offset;
	ut32 data_size;
	ut32 module_name_offset;
	ut32 module_name_size;
	ut32 segment_tab_offset;
	ut32 segment_tab_num;
	ut32 named_exp_offset;
	ut32 named_exp_num;
	ut32 indexed_exp_offset;
	ut32 indexed_exp_num;
	ut32 exp_strings_offset;
	ut32 exp_strings_size;
	ut32 exp_tree_offset;
	ut32 exp_tree_num;
	ut32 imp_module_offset;
	ut32 imp_module_num;
	ut32 imp_patches_offset;
	ut32 imp_patches_num;
	ut32 named_imp_offset;
	ut32 named_imp_num;
	ut32 indexed_imp_offset;
	ut32 indexed_imp_num;
	ut32 anon_imp_offset;
	ut32 anon_imp_num;
	ut32 imp_string_offset;
	ut32 imp_string_size;
	ut32 unk8_offset;
	ut32 unk8_num;
	ut32 reloc_patches_offset;
	ut32 reloc_patches_num;
	ut32 unk9_offset;
	ut32 unk9_num;
} __attribute__((packed));

struct n3ds_cro_seg_tab_entry
{
	ut32 offset;
	ut32 size;
	ut32 type;
};

struct n3ds_cro_named_exp_entry
{
	ut32 name_offset;
	ut32 segment_offset;
};

#endif