#include "framework.h"
#include "PLPFidoExample.h"
#include "PLPFidoExampleDlg.h"

#include <memory>
#include <thread>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CPLPFidoExampleDlg::CPLPFidoExampleDlg(CWnd* pParent /*=nullptr*/)
  : CDialogEx(IDD_PLPFIDOEXAMPLE_DIALOG, pParent)
  , m_rpId(_T("example.phraselock.com"))
  , m_userName(_T("alice"))
{
}

void CPLPFidoExampleDlg::DoDataExchange(CDataExchange* pDX)
{
  CDialogEx::DoDataExchange(pDX);
  DDX_Control(pDX, IDC_COMBO_DEVICE, m_comboDevice);
  DDX_Control(pDX, IDC_EDIT_LOG, m_editLog);
  DDX_Text(pDX, IDC_EDIT_RPID, m_rpId);
  DDX_Text(pDX, IDC_EDIT_USER, m_userName);
  DDX_Text(pDX, IDC_EDIT_PIN, m_pin);
  DDX_Check(pDX, IDC_CHECK_RK, m_discoverable);
  DDX_Check(pDX, IDC_CHECK_ROAMING, m_roamingOnly);
}

BEGIN_MESSAGE_MAP(CPLPFidoExampleDlg, CDialogEx)
  ON_BN_CLICKED(IDC_BTN_REFRESH, &CPLPFidoExampleDlg::OnBnClickedRefresh)
  ON_BN_CLICKED(IDC_BTN_INFO, &CPLPFidoExampleDlg::OnBnClickedInfo)
  ON_BN_CLICKED(IDC_BTN_REGISTER, &CPLPFidoExampleDlg::OnBnClickedRegister)
  ON_BN_CLICKED(IDC_BTN_SIGNIN, &CPLPFidoExampleDlg::OnBnClickedSignIn)
  ON_BN_CLICKED(IDC_BTN_CLEAR, &CPLPFidoExampleDlg::OnBnClickedClear)
  ON_MESSAGE(WM_APP_LOG, &CPLPFidoExampleDlg::OnAppLog)
  ON_MESSAGE(WM_APP_DONE, &CPLPFidoExampleDlg::OnAppDone)
  ON_WM_GETMINMAXINFO()
END_MESSAGE_MAP()

BOOL CPLPFidoExampleDlg::OnInitDialog()
{
  CDialogEx::OnInitDialog();

  CRect rc;
  GetWindowRect(&rc);
  m_minSize = rc.Size();

  m_logFont.CreatePointFont(100, _T("Consolas"));
  m_editLog.SetFont(&m_logFont);
  m_editLog.SetLimitText(0);

  Log(FidoDemo::IsElevated()
    ? _T("Process is elevated: direct HID access to FIDO keys is possible.")
    : _T("Process is NOT elevated: Windows blocks direct HID access to FIDO keys - use 'windows://hello' (routes USB keys via webauthn.dll too) or run as Administrator."));

  OnBnClickedRefresh();
  return TRUE;
}

void CPLPFidoExampleDlg::OnCancel()
{
  // A worker thread still uses m_fido - don't tear down the dialog underneath it
  if (m_busy) {
    Log(_T("Operation in progress - complete or cancel it on the authenticator first (timeout 60 s)."));
    return;
  }
  CDialogEx::OnCancel();
}

void CPLPFidoExampleDlg::OnBnClickedRefresh()
{
  Log(_T("Enumerating devices ..."));
  m_devices = FidoDemo::ListDevices([this](const std::string& s) { Log(CString(CA2W(s.c_str(), CP_UTF8))); });

  m_comboDevice.ResetContent();
  for (const auto& d : m_devices)
    m_comboDevice.AddString(CString(CA2W(d.label.c_str(), CP_UTF8)));
  if (!m_devices.empty())
    m_comboDevice.SetCurSel(0);
}

void CPLPFidoExampleDlg::OnBnClickedInfo()
{
  std::string path = SelectedDevicePath();
  RunAsync([this, path](const FidoDemo::LogFn& log) {
    FidoDemo::DeviceInfo(path, log);
  });
}

void CPLPFidoExampleDlg::OnBnClickedRegister()
{
  UpdateData(TRUE);
  std::string path = SelectedDevicePath();
  std::string rpId = ToUtf8(m_rpId);
  std::string user = ToUtf8(m_userName);
  std::string pin = ToUtf8(m_pin);
  bool rk = m_discoverable != FALSE;
  bool roaming = m_roamingOnly != FALSE;
  RunAsync([this, path, rpId, user, pin, rk, roaming](const FidoDemo::LogFn& log) {
    m_fido.Register(path, rpId, user, pin, rk, roaming, log);
  });
}

void CPLPFidoExampleDlg::OnBnClickedSignIn()
{
  UpdateData(TRUE);
  std::string path = SelectedDevicePath();
  std::string rpId = ToUtf8(m_rpId);
  std::string pin = ToUtf8(m_pin);
  bool rk = m_discoverable != FALSE;
  bool roaming = m_roamingOnly != FALSE;
  RunAsync([this, path, rpId, pin, rk, roaming](const FidoDemo::LogFn& log) {
    m_fido.SignIn(path, rpId, pin, rk, roaming, log);
  });
}

void CPLPFidoExampleDlg::OnBnClickedClear()
{
  m_editLog.SetWindowText(_T(""));
}

void CPLPFidoExampleDlg::OnGetMinMaxInfo(MINMAXINFO* lpMMI)
{
  CDialogEx::OnGetMinMaxInfo(lpMMI);
  if (m_minSize.cx > 0) {
    lpMMI->ptMinTrackSize.x = m_minSize.cx;
    lpMMI->ptMinTrackSize.y = m_minSize.cy;
  }
}

LRESULT CPLPFidoExampleDlg::OnAppLog(WPARAM, LPARAM lParam)
{
  std::unique_ptr<CString> text(reinterpret_cast<CString*>(lParam));
  Log(*text);
  return 0;
}

LRESULT CPLPFidoExampleDlg::OnAppDone(WPARAM, LPARAM)
{
  SetBusy(false);
  Log(_T(""));
  return 0;
}

void CPLPFidoExampleDlg::Log(const CString& text)
{
  int len = m_editLog.GetWindowTextLength();
  m_editLog.SetSel(len, len);
  m_editLog.ReplaceSel(text + _T("\r\n"));
}

FidoDemo::LogFn CPLPFidoExampleDlg::MakeThreadLogger() const
{
  HWND hwnd = GetSafeHwnd();
  return [hwnd](const std::string& s) {
    auto* text = new CString(CA2W(s.c_str(), CP_UTF8));
    if (!::PostMessage(hwnd, WM_APP_LOG, 0, reinterpret_cast<LPARAM>(text)))
      delete text;
  };
}

std::string CPLPFidoExampleDlg::SelectedDevicePath() const
{
  int sel = m_comboDevice.GetCurSel();
  if (sel < 0 || sel >= static_cast<int>(m_devices.size()))
    return {};
  return m_devices[sel].path;
}

std::string CPLPFidoExampleDlg::ToUtf8(const CString& s)
{
  return std::string(CW2A(s, CP_UTF8));
}

void CPLPFidoExampleDlg::RunAsync(std::function<void(const FidoDemo::LogFn&)> work)
{
  SetBusy(true);
  FidoDemo::LogFn log = MakeThreadLogger();
  HWND hwnd = GetSafeHwnd();
  std::thread([work = std::move(work), log, hwnd]() {
    work(log);
    ::PostMessage(hwnd, WM_APP_DONE, 0, 0);
  }).detach();
}

void CPLPFidoExampleDlg::SetBusy(bool busy)
{
  m_busy = busy;
  for (int id : { IDC_COMBO_DEVICE, IDC_BTN_REFRESH, IDC_BTN_INFO, IDC_BTN_REGISTER, IDC_BTN_SIGNIN })
    GetDlgItem(id)->EnableWindow(!busy);
}
