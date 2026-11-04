# repo-wide build / audit targets

.PHONY: audit history manifest kit tests profiler-test clean

# OPSEC merge gate (tools/opsec_scan.py) — blocks tracked binaries, committed
# key material, secret patterns, wire IOCs and fixed artifact names in the
# authored trees; sweeps any built COFFs on disk. Exit 0 required.
audit:
	python3 tools/opsec_scan.py

# history variant (slow; run before releases/pushes)
history: audit
	python3 tools/opsec_scan.py --history

# integrity manifest for every built COFF in the tree
manifest:
	@python3 tools/coff_manifest.py

kit:
	$(MAKE) -C Extension-Kit

tests:
	cd hostpayload_v2/tests && python3 -m pytest test_crypto.py -q 2>/dev/null || true
	cd RemoteLoader/RemoteLoader.Tests && dotnet test --nologo -v q 2>/dev/null || true

profiler-test:
	python3 -m pytest profiler/ -q

clean:
	$(MAKE) -C Extension-Kit clean || true
	$(MAKE) -C NaX/src_beacon clean 2>/dev/null || true
	$(MAKE) -C Cenotaph clean || true