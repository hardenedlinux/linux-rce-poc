CFLAGS = -O2 -g -static -pthread
LABBIN = ../lab/bin
SPRAYBIN = ../exp/bin

# Every binary the exploit chain and the leak/trigger tooling stages into the
# guest.  A fresh clone must be able to build the whole set with
# `make -C exp exploit`.  The target-side reclaim sprays used by
# lab/campaign.sh are listed separately because they live in exp/bin.
EXPLOIT_SRCS = mpstorm3.c rce_prep.c acceptor.c attr_spray.c \
	avnspray.c avnhold.c keyhold.c emspray.c trgspray.c synthspray.c \
	filespray.c kmsgspray.c ssa_spray.c leakspray.c \
	exp_tcp.c exp_mptcp.c exp_migrate.c

SPRAY_SRCS = keyspray.c unixspray.c afspray.c

EXPLOIT_BINS = $(EXPLOIT_SRCS:.c=)
SPRAY_BINS = $(addprefix $(SPRAYBIN)/,$(SPRAY_SRCS:.c=))

all: $(LABBIN)/mpstorm3 $(LABBIN)/mpstorm3_mix4

exploit: $(addprefix $(LABBIN)/,$(EXPLOIT_BINS)) $(LABBIN)/mpstorm3_mix4 $(SPRAY_BINS)

# Historical name used by lab/campaign.sh (same source as mpstorm3).
$(LABBIN)/mpstorm3_mix4: mpstorm3.c
	mkdir -p $(LABBIN)
	$(CC) $(CFLAGS) -o $@ $<

$(LABBIN)/%: %.c
	mkdir -p $(LABBIN)
	$(CC) $(CFLAGS) -o $@ $<

$(SPRAYBIN)/%: %.c
	mkdir -p $(SPRAYBIN)
	$(CC) $(CFLAGS) -o $@ $<

# Convenience target for the three sprays used by the campaign.
sprays: $(SPRAY_BINS)

clean:
	rm -f $(addprefix $(LABBIN)/,$(EXPLOIT_BINS) mpstorm3_mix4) $(SPRAY_BINS)

.PHONY: all exploit sprays clean
