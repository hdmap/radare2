OBJ_NIN3DSCRO=bin_nin3dscro.o

STATIC_OBJ+=${OBJ_NIN3DSCRO}
TARGET_NIN3DSCRO=bin_nin3dscro.${EXT_SO}

ALL_TARGETS+=${TARGET_NIN3DSCRO}

${TARGET_NIN3DSCRO}: ${OBJ_NIN3DSCRO}
	${CC} $(call libname,bin_nin3dscro) ${CFLAGS} $(OBJ_NIN3DSCRO) $(LINK) $(LDFLAGS) \
	-L../../magic -lr_magic