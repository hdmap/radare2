#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>

#include "nin/n3dscro.h"

static bool check_bytes(const ut8 *buf, ut64 length);

static struct n3ds_cro_hdr loaded_header;

static bool check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < sizeof(struct n3ds_cro_hdr))
		return false;
	return (!memcmp(buf + 0x80 /* skip hash table */, "CRO0", 4));
}

static void* load_bytes(RBinFile *arhc, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	return memcpy(&loaded_header, buf, sizeof(struct n3ds_cro_hdr));
}

static bool load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer(arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size(arch->buf) : 0;
	if (!arch || !arch->o)
		return false;
	arch->o->bin_obj = load_bytes(arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	return check_bytes(bytes, sz);
}

static int destroy(RBinFile *arch) {
	r_buf_free(arch->buf);
	arch->buf = NULL;
	return true;
}

static RList* sections(RBinFile *arch) {
	RList *ret = r_list_new();
	RBinSection *section = NULL;
	struct n3ds_cro_seg_tab_entry table_entry;
	int i;
	
	if (!ret)
		return NULL;
	
	for (i = 0; i < loaded_header.segment_tab_num; i++) {
		r_buf_read_at(arch->buf, loaded_header.segment_tab_offset + i * 12, &table_entry, 12);
		
		if (table_entry.size) {
			section = R_NEW0(RBinSection);
			section->paddr = table_entry.offset;
			section->size = table_entry.size;
			section->srwx = r_str_rwx ("mrwx");
			section->add = true;
			
			switch (table_entry.type) {
				case 0: 
					strncpy(section->name, ".text", R_BIN_SIZEOF_STRINGS);
					break;
				case 1:
					strncpy(section->name, ".rodata", R_BIN_SIZEOF_STRINGS);
					break;
				case 2:
					strncpy(section->name, ".data", R_BIN_SIZEOF_STRINGS);
					break;
				case 3:
					strncpy(section->name, ".bss", R_BIN_SIZEOF_STRINGS);
					break;
				default:
					strncpy(section->name, ".unknown", R_BIN_SIZEOF_STRINGS);
					break;
			}
			
			r_list_append(ret, section);
		}
	}
	
	return ret;
}

static ut32 resolveOffset(ut32 offset, RBinFile *arch) {
	ut32 seg_offset;
	int segment = offset & 0xF;
	
	r_buf_read_at(arch->buf, loaded_header.segment_tab_offset + segment * 12, &seg_offset, 4);
	
	return /*seg_offset + */(offset >> 4);
}

static RList* symbols(RBinFile *arch) {
	RList *ret = r_list_new();
	RBinSymbol *symbol = NULL;
	struct n3ds_cro_named_exp_entry ne_entry;
	ut32 ie_offset;
	int i;
	char symname[R_BIN_SIZEOF_STRINGS + 1];
	
	if (!ret)
		return NULL;
	
	for (i = 0; i < loaded_header.named_exp_num; i++) {
		r_buf_read_at(arch->buf, loaded_header.named_exp_offset + i * 8, &ne_entry, 8);
		
		symbol = R_NEW0(RBinSymbol);
		symbol->paddr = symbol->vaddr = resolveOffset(ne_entry.segment_offset, arch);
		
		r_buf_read_at(arch->buf, ne_entry.name_offset, symname, R_BIN_SIZEOF_STRINGS);
		symbol->name = strdup(symname);
		
		symbol->size = 1;
		symbol->ordinal = i;
		
		r_list_append(ret, symbol); 
	}
	
	for (i = 0; i < loaded_header.indexed_exp_num; i++) {
		r_buf_read_at(arch->buf, loaded_header.indexed_exp_offset + i * 4, &ie_offset, 4);
		
		symbol = R_NEW0(RBinSymbol);
		symbol->paddr = resolveOffset(ie_offset, arch);
		symbol->name = r_str_newf ("Ordinal_%i", i);
		
		r_list_append(ret, symbol);
	}
	
	return ret;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0(RBinInfo);
	
	if (!ret)
		return NULL;
	
	ret->type = strdup("CRO");
	ret->machine = strdup ("Nintendo 3DS");
	ret->os = strdup ("n3ds");
	ret->arch = strdup ("arm");
	ret->bits = 32;
	
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_nin3dscro = {
	.name = "nin3dscro",
	.desc = "Nintendo 3DS CRO format r_bin plugin",
	.license = "LGPL3",
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_nin3dscro,
	.version = R2_VERSION
};
#endif
