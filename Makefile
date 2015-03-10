test: kmod/abuse.ko userland/abctl
	@lsmod | grep -q abuse || sudo insmod kmod/abuse.ko
	sudo $(PWD)/test.sh

kmod/abuse.ko:
	(cd kmod; $(MAKE))

userland/abctl:
	(cd userland; $(MAKE))

clean:
	(cd userland; $(MAKE) clean)
	(cd kmod; $(MAKE) clean)
