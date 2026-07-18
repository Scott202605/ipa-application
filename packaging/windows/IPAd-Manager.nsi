Unicode true
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!ifndef VERSION
  !error "VERSION is required"
!endif
!ifndef DEB
  !error "DEB is required"
!endif
!ifndef DEBSHA
  !error "DEBSHA is required"
!endif
!ifndef OUTPUT
  !error "OUTPUT is required"
!endif
!ifndef SOURCE
  !error "SOURCE is required"
!endif

Name "IPAd Manager ${VERSION}"
OutFile "${OUTPUT}\IPAd-Manager-Setup-${VERSION}-x64.exe"
InstallDir "$PROGRAMFILES64\IPAd Manager"
InstallDirRegKey HKLM "Software\IPAd Manager" "InstallDir"
BrandingText "IPAd Manager"
ShowInstDetails show
ShowUninstDetails show

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "English"

Section "IPAd Manager" SecMain
  SetRegView 64
  SetOutPath "$INSTDIR"
  File /oname=ipad-manager.deb "${DEB}"
  File "${SOURCE}\install-ipad-manager.ps1"
  File "${SOURCE}\uninstall-ipad-manager.ps1"
  File "${SOURCE}\launch-ipad-manager.cmd"
  File "${SOURCE}\health-ipad-manager.cmd"
  File "${SOURCE}\diagnostics-ipad-manager.cmd"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\IPAd Manager" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\IPAd Manager" "DisplayName" "IPAd Manager"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\IPAd Manager" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\IPAd Manager" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  CreateDirectory "$SMPROGRAMS\IPAd Manager"
  CreateShortcut "$SMPROGRAMS\IPAd Manager\Launch IPAd Manager.lnk" "$INSTDIR\launch-ipad-manager.cmd"
  CreateShortcut "$SMPROGRAMS\IPAd Manager\Health Check.lnk" "$INSTDIR\health-ipad-manager.cmd"
  CreateShortcut "$SMPROGRAMS\IPAd Manager\Export Diagnostics.lnk" "$INSTDIR\diagnostics-ipad-manager.cmd"
  CreateShortcut "$SMPROGRAMS\IPAd Manager\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\install-ipad-manager.ps1" -DebPath "$INSTDIR\ipad-manager.deb" -ExpectedSha256 "${DEBSHA}"' $0
  IntCmp $0 0 install_ok
    MessageBox MB_ICONSTOP "IPAd Manager installation failed with exit code $0. Review the installation log."
    Abort
  install_ok:
SectionEnd

Section "Uninstall"
  SetRegView 64
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\uninstall-ipad-manager.ps1"' $0
  IntCmp $0 0 uninstall_ok
    MessageBox MB_ICONSTOP "IPAd Manager removal from Ubuntu failed with exit code $0."
    Abort
  uninstall_ok:
  Delete "$SMPROGRAMS\IPAd Manager\Launch IPAd Manager.lnk"
  Delete "$SMPROGRAMS\IPAd Manager\Health Check.lnk"
  Delete "$SMPROGRAMS\IPAd Manager\Export Diagnostics.lnk"
  Delete "$SMPROGRAMS\IPAd Manager\Uninstall.lnk"
  RMDir "$SMPROGRAMS\IPAd Manager"
  Delete "$INSTDIR\*"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "Software\IPAd Manager"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\IPAd Manager"
SectionEnd
