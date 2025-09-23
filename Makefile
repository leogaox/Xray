.PHONY: install status uninstall purge
install:  ; sudo ./scripts/xray_onekey.sh install
status:   ; sudo ./scripts/xray_onekey.sh status
uninstall:; sudo ./scripts/xray_onekey.sh uninstall
purge:    ; sudo ./scripts/xray_onekey.sh purge
