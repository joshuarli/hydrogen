ROOT:=		$(abspath ../..)
include $(ROOT)/dev/toolchain.lock
CC:=		$(ROOT)/.work/toolchain/$(LLVM_DIR)/bin/clang
SYSROOT:=	$(ROOT)/.work/sysroot
OUT:=		$(ROOT)/.work/build/mini_chromium
CFLAGS:=	--sysroot=$(SYSROOT) -O2 -g -Wall -Wextra -Werror

STATIC_FIXTURES:=	hello_static hello_pthread crash silent_exit hang duplicate_result meminfo writev_iov wait_nochild low_user_va vm_isolation poll_xproc cow_stress kill_race exec_contract process_stress shmem_xproc ipc_xproc creds_procfs seccomp mmap_bad_fd scm_rights
DYNAMIC_FIXTURES:=	hello_stdio exec_contract_helper

all: $(OUT)/mini_chromium $(OUT)/mini_chromium_raw $(addprefix $(OUT)/fixtures/,$(STATIC_FIXTURES) $(DYNAMIC_FIXTURES)) $(OUT)/fixtures/vm_isolation_dyn $(OUT)/fixtures/cow_stress_dyn

$(OUT)/mini_chromium: mini_chromium.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Wno-sign-compare -pthread $< -o $@

$(OUT)/mini_chromium_raw: mini_chromium_raw.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -static -nostdlib -ffreestanding -fno-builtin -fno-stack-protector $< -o $@

$(addprefix $(OUT)/fixtures/,$(STATIC_FIXTURES)): $(OUT)/fixtures/%: fixtures/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -static -pthread $< -o $@

$(addprefix $(OUT)/fixtures/,$(DYNAMIC_FIXTURES)): $(OUT)/fixtures/%: fixtures/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -pthread $< -o $@

$(OUT)/fixtures/vm_isolation_dyn: fixtures/vm_isolation.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -pthread $< -o $@

$(OUT)/fixtures/cow_stress_dyn: fixtures/cow_stress.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -pthread $< -o $@

.PHONY: all
