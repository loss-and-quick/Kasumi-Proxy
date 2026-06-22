; NSIS installer hooks: register the privileged data-path service so the installed
; GUI runs unprivileged with no per-launch UAC. The installer is already elevated,
; so --install/--uninstall need no extra prompt. The helper sidecar sits next to
; the app exe in $INSTDIR. MSI/portable builds fall back to first-run self-install.

!macro NSIS_HOOK_POSTINSTALL
  ExecWait '"$INSTDIR\kasumi-helper.exe" --install'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ExecWait '"$INSTDIR\kasumi-helper.exe" --uninstall'
!macroend
