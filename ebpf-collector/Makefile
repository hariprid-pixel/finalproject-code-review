BPFTOOL   ?= bpftool
CLANG     ?= clang
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf)

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

BPF_SRC   := bpf/collector.bpf.c
BPF_OBJ   := bpf/collector.bpf.o
SKEL      := src/collector.skel.h
VMLINUX   := bpf/vmlinux.h
DAEMON_SRC := src/collector.c
DAEMON_BIN := collector

.PHONY: all clean vmlinux

all: $(DAEMON_BIN)

# Dump the running kernel's BTF as a header so BPF CO-RE has struct layouts
# to compile against. Only needs to be regenerated if the kernel changes.
$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I bpf -I include \
		-c $(BPF_SRC) -o $(BPF_OBJ)

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL)

$(DAEMON_BIN): $(SKEL) $(DAEMON_SRC)
	$(CLANG) -g -O2 $(LIBBPF_CFLAGS) \
		-I src -I include \
		$(DAEMON_SRC) -o $(DAEMON_BIN) $(LIBBPF_LIBS)

clean:
	rm -f $(BPF_OBJ) $(SKEL) $(DAEMON_BIN) $(VMLINUX)
